#!/usr/bin/env python3
"""Run and audit the source-only T8 assertion-lineage census."""

from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_SCRIPT = ROOT / "scripts" / "bench" / "validate_t8_lineage_contract.py"
VERIFIER_SCRIPT = ROOT / "scripts" / "cert" / "verify_assertion_lineage.py"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
REVISION_RE = re.compile(r"[0-9a-f]{40}")
RECORD_SCHEMA = "euf-viper.assertion-lineage-census-record.v1"
AUDIT_SCHEMA = "euf-viper.assertion-lineage-census-audit.v1"
ERROR_CATEGORIES = {
    "hash_error",
    "lineage_error",
    "parse_error",
    "unsupported_accounting_error",
    "verifier_error",
}
RECORD_KEYS = {
    "assertions",
    "binary_sha256",
    "build_git_revision",
    "build_source_revision_sha256",
    "error_category",
    "ledger_sha256",
    "lineage_sha256",
    "objects",
    "parser_source_revision_sha256",
    "physical_device",
    "physical_inode",
    "python_path",
    "python_sha256",
    "python_version",
    "reason",
    "relative_path",
    "schema",
    "sequence",
    "source_bytes",
    "source_sha256",
    "status",
    "unsupported_diagnostics",
}


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CONTRACT = load_module("validate_t8_lineage_contract", CONTRACT_SCRIPT)
VERIFIER = load_module("verify_assertion_lineage", VERIFIER_SCRIPT)


class CensusError(ValueError):
    """Raised when census inputs, rows, or aggregates violate the contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CensusError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CensusError(f"cannot encode canonical JSON: {error}") from error


def strict_json_line(line: bytes, *, where: str) -> dict[str, Any]:
    try:
        value = json.loads(
            line.decode("utf-8"),
            object_pairs_hook=VERIFIER.reject_duplicate_keys,
            parse_constant=VERIFIER.reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise CensusError(f"{where}: malformed strict JSON: {error}") from error
    require(type(value) is dict, f"{where}: expected object")
    require(canonical_bytes(value) == line, f"{where}: non-canonical JSON")
    return value


def load_manifest(path: Path, expected_sha256: str, expected_count: int) -> list[dict[str, Any]]:
    content, _, _ = VERIFIER.read_no_follow(path)
    require(hashlib.sha256(content).hexdigest() == expected_sha256, "manifest SHA-256 mismatch")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(content.splitlines(keepends=True), 1):
        require(line.endswith(b"\n"), f"manifest line {line_number}: missing newline")
        row = strict_json_line(line, where=f"manifest line {line_number}")
        for key in ("bytes", "relative_path", "sha256"):
            require(key in row, f"manifest line {line_number}: missing {key}")
        require(type(row["bytes"]) is int and row["bytes"] >= 0, f"manifest line {line_number}: invalid bytes")
        require(
            type(row["sha256"]) is str and SHA256_RE.fullmatch(row["sha256"]) is not None,
            f"manifest line {line_number}: invalid SHA-256",
        )
        relative = PurePosixPath(row["relative_path"])
        require(
            not relative.is_absolute() and ".." not in relative.parts and str(relative) == row["relative_path"],
            f"manifest line {line_number}: unsafe relative path",
        )
        rows.append(row)
    require(len(rows) == expected_count, f"manifest has {len(rows)} rows, expected {expected_count}")
    paths = [row["relative_path"] for row in rows]
    require(len(set(paths)) == expected_count, "manifest relative paths are not unique")
    return rows


def validate_environment(expected: dict[str, str | None]) -> None:
    for name, required in expected.items():
        actual = os.environ.get(name)
        if required is None:
            require(actual is None, f"parser environment drift: {name} must be unset")
        else:
            require(actual == required, f"parser environment drift: {name} must be {required!r}")


def classify_failure(message: str) -> str:
    lowered = message.lower()
    if "unsupported-accounting" in lowered:
        return "unsupported_accounting_error"
    if "stale-source" in lowered or "sha-256" in lowered or "source size" in lowered:
        return "hash_error"
    if "lineage" in lowered or "origin" in lowered or "span" in lowered:
        return "lineage_error"
    return "parse_error"


def record_error(
    sequence: int,
    row: dict[str, Any],
    category: str,
    reason: str,
    *,
    binary_sha256: str,
    physical_device: int | None,
    physical_inode: int | None,
    python_identity: dict[str, str],
) -> dict[str, Any]:
    require(category in ERROR_CATEGORIES, f"unknown error category {category}")
    return {
        "assertions": None,
        "binary_sha256": binary_sha256,
        "build_git_revision": None,
        "build_source_revision_sha256": None,
        "error_category": category,
        "ledger_sha256": None,
        "lineage_sha256": None,
        "objects": None,
        "parser_source_revision_sha256": None,
        "physical_device": physical_device,
        "physical_inode": physical_inode,
        "python_path": python_identity["path"],
        "python_sha256": python_identity["sha256"],
        "python_version": python_identity["version"],
        "reason": reason[:4096],
        "relative_path": row["relative_path"],
        "schema": RECORD_SCHEMA,
        "sequence": sequence,
        "source_bytes": row["bytes"],
        "source_sha256": row["sha256"],
        "status": "error",
        "unsupported_diagnostics": None,
    }


def run_one(
    sequence: int,
    row: dict[str, Any],
    source_root: Path,
    binary: Path,
    binary_sha256: str,
    revision: str,
    temporary: Path,
    python_identity: dict[str, str],
) -> dict[str, Any]:
    source = source_root.joinpath(*PurePosixPath(row["relative_path"]).parts)
    physical_device: int | None = None
    physical_inode: int | None = None
    try:
        content, source_fingerprint, _ = VERIFIER.read_no_follow(source)
        physical_device = source_fingerprint.device
        physical_inode = source_fingerprint.inode
        require(len(content) == row["bytes"], "source size differs from manifest")
        require(hashlib.sha256(content).hexdigest() == row["sha256"], "source SHA-256 differs from manifest")
    except (CensusError, VERIFIER.LineageError) as error:
        return record_error(
            sequence,
            row,
            "hash_error",
            str(error),
            binary_sha256=binary_sha256,
            physical_device=physical_device,
            physical_inode=physical_inode,
            python_identity=python_identity,
        )

    ledger_path = temporary / f"{sequence:06}.lineage.json"
    completed = subprocess.run(
        [
            str(binary),
            "lineage",
            str(source),
            "--source-sha256",
            row["sha256"],
            "--source-bytes",
            str(row["bytes"]),
            "--out",
            str(ledger_path),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace")
        return record_error(
            sequence,
            row,
            classify_failure(message),
            f"lineage command exited {completed.returncode}: {message}",
            binary_sha256=binary_sha256,
            physical_device=physical_device,
            physical_inode=physical_inode,
            python_identity=python_identity,
        )
    try:
        VERIFIER.validate_ledger(source, ledger_path)
        ledger_content, _, _ = VERIFIER.read_no_follow(ledger_path)
        ledger = VERIFIER.strict_json_bytes(ledger_content, where="generated ledger")
        require(ledger["build"]["git_revision"] == revision, "build revision differs from campaign revision")
        require(ledger["build"]["git_dirty"] is False, "lineage binary was built from a dirty tree")
        require(
            ledger["parser"]["requested_scoped_let_mode"] == "auto",
            "lineage parser scoped-let mode differs from campaign",
        )
        require(
            ledger["parser"]["legacy_preprocess_term_limit"] == 1024,
            "lineage legacy preprocessing limit differs from campaign",
        )
        require(ledger["unsupported_accounting_complete"] is True, "unsupported accounting is incomplete")
    except (CensusError, VERIFIER.LineageError, KeyError, TypeError) as error:
        return record_error(
            sequence,
            row,
            "verifier_error",
            str(error),
            binary_sha256=binary_sha256,
            physical_device=physical_device,
            physical_inode=physical_inode,
            python_identity=python_identity,
        )
    return {
        "assertions": ledger["counts"]["source_assertions"],
        "binary_sha256": binary_sha256,
        "build_git_revision": ledger["build"]["git_revision"],
        "build_source_revision_sha256": ledger["build"]["source_revision_sha256"],
        "error_category": None,
        "ledger_sha256": hashlib.sha256(ledger_content).hexdigest(),
        "lineage_sha256": ledger["lineage_sha256"],
        "objects": ledger["counts"]["objects"],
        "parser_source_revision_sha256": ledger["parser"]["source_revision_sha256"],
        "physical_device": physical_device,
        "physical_inode": physical_inode,
        "python_path": python_identity["path"],
        "python_sha256": python_identity["sha256"],
        "python_version": python_identity["version"],
        "reason": None,
        "relative_path": row["relative_path"],
        "schema": RECORD_SCHEMA,
        "sequence": sequence,
        "source_bytes": row["bytes"],
        "source_sha256": row["sha256"],
        "status": "verified",
        "unsupported_diagnostics": ledger["counts"]["diagnostics"],
    }


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def run_shard(args: argparse.Namespace) -> None:
    root = args.root.resolve(strict=True)
    contract = CONTRACT.load_contract(args.contract)
    CONTRACT.validate_contract(contract)
    CONTRACT.validate_release_metadata(root, contract)
    validate_environment(contract["parser_environment"])
    require(REVISION_RE.fullmatch(args.revision) is not None, "campaign revision must be 40 lowercase hex digits")
    require(0 <= args.shard_index < args.shard_count, "shard index is out of range")
    require(args.shard_count == contract["execution"]["shard_count"], "shard count differs from contract")
    binary = args.binary.resolve(strict=True)
    actual_binary_sha256 = sha256_file(binary)
    require(actual_binary_sha256 == args.binary_sha256, "binary SHA-256 mismatch")
    python_path = Path(sys.executable).resolve(strict=True)
    python_identity = {
        "path": str(python_path),
        "sha256": sha256_file(python_path),
        "version": f"Python {platform.python_version()}",
    }
    require(python_identity["sha256"] == args.python_sha256, "Python SHA-256 mismatch")
    require(python_identity["version"] == args.python_version, "Python version mismatch")
    population = contract["population"]
    manifest = load_manifest(
        args.manifest,
        population["full_manifest_sha256"],
        population["expected_records"],
    )
    selected = [
        (sequence, row)
        for sequence, row in enumerate(manifest)
        if sequence % args.shard_count == args.shard_index
    ]
    records: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="euf-viper-lineage-census-") as temporary_name:
        temporary = Path(temporary_name)
        for sequence, row in selected:
            records.append(
                run_one(
                    sequence,
                    row,
                    args.source_root.resolve(strict=True),
                    binary,
                    actual_binary_sha256,
                    args.revision,
                    temporary,
                    python_identity,
                )
            )
    atomic_write(args.out, b"".join(canonical_bytes(record) for record in records))


def load_record_files(paths: Iterable[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths:
        content, _, _ = VERIFIER.read_no_follow(path)
        for line_number, line in enumerate(content.splitlines(keepends=True), 1):
            require(line.endswith(b"\n"), f"{path}:{line_number}: missing newline")
            record = strict_json_line(line, where=f"{path}:{line_number}")
            require(set(record) == RECORD_KEYS, f"{path}:{line_number}: record key mismatch")
            require(record["schema"] == RECORD_SCHEMA, f"{path}:{line_number}: schema mismatch")
            validate_record(record, where=f"{path}:{line_number}")
            records.append(record)
    return records


def validate_record(record: dict[str, Any], *, where: str) -> None:
    require(
        type(record["sequence"]) is int and record["sequence"] >= 0,
        f"{where}: invalid sequence",
    )
    require(
        type(record["relative_path"]) is str,
        f"{where}: invalid relative path",
    )
    relative = PurePosixPath(record["relative_path"])
    require(
        not relative.is_absolute()
        and ".." not in relative.parts
        and str(relative) == record["relative_path"],
        f"{where}: invalid relative path",
    )
    require(
        type(record["source_bytes"]) is int and record["source_bytes"] >= 0,
        f"{where}: invalid source size",
    )
    for field in ("binary_sha256", "python_sha256", "source_sha256"):
        require(
            type(record[field]) is str and SHA256_RE.fullmatch(record[field]) is not None,
            f"{where}: invalid {field}",
        )
    require(
        type(record["python_path"]) is str
        and Path(record["python_path"]).is_absolute(),
        f"{where}: invalid Python path",
    )
    require(
        type(record["python_version"]) is str
        and re.fullmatch(r"Python [0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9.+-]*)?", record["python_version"])
        is not None,
        f"{where}: invalid Python version",
    )
    require(record["status"] in {"error", "verified"}, f"{where}: invalid status")
    if record["status"] == "verified":
        require(record["error_category"] is None, f"{where}: verified row has an error category")
        require(record["reason"] is None, f"{where}: verified row has a reason")
        require(
            type(record["build_git_revision"]) is str
            and REVISION_RE.fullmatch(record["build_git_revision"]) is not None,
            f"{where}: invalid build revision",
        )
        for field in (
            "build_source_revision_sha256",
            "ledger_sha256",
            "lineage_sha256",
            "parser_source_revision_sha256",
        ):
            require(
                type(record[field]) is str
                and SHA256_RE.fullmatch(record[field]) is not None,
                f"{where}: invalid {field}",
            )
        for field in ("assertions", "objects", "unsupported_diagnostics"):
            require(
                type(record[field]) is int and record[field] >= 0,
                f"{where}: invalid {field}",
            )
        for field in ("physical_device", "physical_inode"):
            require(
                type(record[field]) is int and record[field] >= 0,
                f"{where}: invalid {field}",
            )
    else:
        require(
            record["error_category"] in ERROR_CATEGORIES,
            f"{where}: invalid error category",
        )
        require(
            type(record["reason"]) is str and bool(record["reason"]),
            f"{where}: missing error reason",
        )
        for field in (
            "assertions",
            "build_git_revision",
            "build_source_revision_sha256",
            "ledger_sha256",
            "lineage_sha256",
            "objects",
            "parser_source_revision_sha256",
            "unsupported_diagnostics",
        ):
            require(record[field] is None, f"{where}: error row has stale {field}")


def audit(args: argparse.Namespace) -> None:
    root = args.root.resolve(strict=True)
    contract = CONTRACT.load_contract(args.contract)
    CONTRACT.validate_contract(contract)
    CONTRACT.validate_release_metadata(root, contract)
    require(REVISION_RE.fullmatch(args.revision) is not None, "campaign revision must be 40 lowercase hex digits")
    records = load_record_files(args.records)
    population = contract["population"]
    expected = population["expected_records"]
    sequences = [record["sequence"] for record in records]
    paths = [record["relative_path"] for record in records]
    physical = [(record["physical_device"], record["physical_inode"]) for record in records]
    statuses = collections.Counter(record["status"] for record in records)
    error_counts = collections.Counter(
        record["error_category"] for record in records if record["error_category"] is not None
    )
    revisions = {record["build_git_revision"] for record in records if record["build_git_revision"] is not None}
    parser_revisions = {
        record["parser_source_revision_sha256"]
        for record in records
        if record["parser_source_revision_sha256"] is not None
    }
    build_revisions = {
        record["build_source_revision_sha256"]
        for record in records
        if record["build_source_revision_sha256"] is not None
    }
    python_hashes = {record["python_sha256"] for record in records}
    python_paths = {record["python_path"] for record in records}
    python_versions = {record["python_version"] for record in records}
    gate = {
        "exact_record_count": len(records) == expected,
        "exact_sequence_set": sorted(sequences) == list(range(expected)),
        "unique_relative_paths": len(set(paths)) == population["expected_unique_relative_paths"],
        "unique_physical_sources": len(set(physical)) == population["expected_unique_device_inode_pairs"],
        "all_records_verified": statuses == {"verified": expected},
        "zero_parse_errors": error_counts["parse_error"] == 0,
        "zero_hash_errors": error_counts["hash_error"] == 0,
        "zero_lineage_errors": error_counts["lineage_error"] == 0,
        "zero_verifier_errors": error_counts["verifier_error"] == 0,
        "zero_unsupported_accounting_errors": error_counts["unsupported_accounting_error"] == 0,
        "exact_build_revision": revisions == {args.revision},
        "single_parser_source_revision": len(parser_revisions) == 1,
        "single_build_source_revision": len(build_revisions) == 1,
        "single_python_path": len(python_paths) == 1,
        "single_python_sha256": len(python_hashes) == 1,
        "single_python_version": len(python_versions) == 1,
        "solver_invocations": 0,
    }
    gate["passed"] = all(
        value is True
        for key, value in gate.items()
        if key not in {"solver_invocations", "passed"}
    ) and gate["solver_invocations"] == 0
    result = {
        "build_git_revision": args.revision,
        "build_source_revision_sha256": next(iter(build_revisions), None),
        "campaign_id": contract["campaign_id"],
        "counts": {
            "errors": dict(sorted(error_counts.items())),
            "records": len(records),
            "statuses": dict(sorted(statuses.items())),
            "unique_physical_sources": len(set(physical)),
            "unique_relative_paths": len(set(paths)),
            "unsupported_diagnostics": sum(
                record["unsupported_diagnostics"] or 0 for record in records
            ),
        },
        "gate": gate,
        "parser_source_revision_sha256": next(iter(parser_revisions), None),
        "python_path": next(iter(python_paths), None),
        "python_sha256": next(iter(python_hashes), None),
        "python_version": next(iter(python_versions), None),
        "schema": AUDIT_SCHEMA,
        "status": "pass" if gate["passed"] else "fail",
    }
    atomic_write(args.out, canonical_bytes(result))
    if not gate["passed"]:
        raise CensusError("lineage census gate failed")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    shard = subparsers.add_parser("run-shard")
    shard.add_argument("--binary", required=True, type=Path)
    shard.add_argument("--binary-sha256", required=True)
    shard.add_argument("--contract", required=True, type=Path)
    shard.add_argument("--manifest", required=True, type=Path)
    shard.add_argument("--out", required=True, type=Path)
    shard.add_argument("--python-sha256", required=True)
    shard.add_argument("--python-version", required=True)
    shard.add_argument("--revision", required=True)
    shard.add_argument("--root", required=True, type=Path)
    shard.add_argument("--shard-count", required=True, type=int)
    shard.add_argument("--shard-index", required=True, type=int)
    shard.add_argument("--source-root", required=True, type=Path)
    shard.set_defaults(func=run_shard)

    audit_parser = subparsers.add_parser("audit")
    audit_parser.add_argument("--contract", required=True, type=Path)
    audit_parser.add_argument("--out", required=True, type=Path)
    audit_parser.add_argument("--records", required=True, nargs="+", type=Path)
    audit_parser.add_argument("--revision", required=True)
    audit_parser.add_argument("--root", required=True, type=Path)
    audit_parser.set_defaults(func=audit)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        args.func(args)
    except (CensusError, CONTRACT.ContractError, VERIFIER.LineageError, OSError) as error:
        print(f"assertion-lineage census failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
