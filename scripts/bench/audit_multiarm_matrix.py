#!/usr/bin/env python3
"""Audit and aggregate a complete sharded multi-arm Williams experiment."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "euf-viper.multiarm-matrix-audit.v1"
HEX64 = frozenset("0123456789abcdef")
RECEIPT_V1 = {
    "schema_version",
    "status",
    "job_id",
    "array_job_id",
    "array_task_id",
    "orchestration_revision",
    "solver_sha256",
    "selection_sha256",
    "manifest_sha256",
    "shard_sha256",
    "task_script_sha256",
    "sbatch_script_sha256",
    "runner_sha256",
    "toolchain_sha256",
    "cpu_model",
    "affinity_cpus",
    "started_at",
    "finished_at",
    "task_exit_code",
}
RECEIPT_V2 = RECEIPT_V1 | {"mode"}


class AuditError(ValueError):
    """The matrix evidence is incomplete, inconsistent, or hash-invalid."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def load_json(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuditError(f"cannot read {context}: {error}") from error
    if type(value) is not dict:
        raise AuditError(f"{context} must be an object")
    return value


def load_jsonl(path: Path, context: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.rstrip("\n"):
                    raise AuditError(f"{context} line {line_number} is blank")
                value = json.loads(line, object_pairs_hook=unique_object)
                if type(value) is not dict:
                    raise AuditError(f"{context} line {line_number} is not an object")
                rows.append(value)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuditError(f"cannot read {context}: {error}") from error
    if not rows:
        raise AuditError(f"{context} is empty")
    return rows


def require_digest(value: Any, context: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in HEX64 for character in value)
    ):
        raise AuditError(f"invalid SHA-256 for {context}")
    return value


def verify_hash(path: Path, expected: str, context: str) -> None:
    require_digest(expected, context)
    if not path.is_file() or path.is_symlink():
        raise AuditError(f"missing regular file for {context}: {path}")
    actual = sha256_file(path)
    if actual != expected:
        raise AuditError(f"hash mismatch for {context}: {actual} != {expected}")


def read_receipt(path: Path) -> dict[str, str]:
    try:
        with path.open(newline="", encoding="ascii") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as error:
        raise AuditError(f"cannot read receipt {path}: {error}") from error
    fields = reader.fieldnames
    if fields is None or len(fields) != len(set(fields)) or len(rows) != 1:
        raise AuditError(f"receipt must have one unique-header row: {path}")
    receipt = rows[0]
    version = receipt.get("schema_version")
    expected = RECEIPT_V1 if version == "1" else RECEIPT_V2 if version == "2" else None
    if expected is None or set(fields) != expected:
        raise AuditError(f"receipt schema drifted: {path}")
    return receipt


def row_identity(row: Mapping[str, Any], context: str) -> tuple[str, str, str]:
    relative_path = row.get("relative_path")
    status = row.get("status")
    digest = row.get("sha256")
    if type(relative_path) is not str or not relative_path or relative_path.startswith("/"):
        raise AuditError(f"{context} has invalid relative_path")
    if status not in {"sat", "unsat"}:
        raise AuditError(f"{context} has invalid expected status")
    return relative_path, str(status), require_digest(digest, f"{context} source")


def verify_manifest_pair(
    selection_rows: Sequence[Mapping[str, Any]],
    manifest_rows: Sequence[Mapping[str, Any]],
) -> list[tuple[str, str, str]]:
    if len(selection_rows) != len(manifest_rows):
        raise AuditError("selection and rebased manifest lengths differ")
    identities: list[tuple[str, str, str]] = []
    for index, (selection, manifest) in enumerate(zip(selection_rows, manifest_rows)):
        left = row_identity(selection, f"selection row {index}")
        right = row_identity(manifest, f"manifest row {index}")
        if left != right:
            raise AuditError(f"selection and manifest row {index} differ")
        source = Path(str(manifest.get("path", "")))
        if not source.is_absolute():
            raise AuditError(f"manifest row {index} path is not absolute")
        identities.append(right)
    if len({identity[0] for identity in identities}) != len(identities):
        raise AuditError("manifest relative paths are duplicated")
    return identities


def read_csv_count(path: Path) -> int:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)):
                raise AuditError(f"raw CSV has an invalid header: {path}")
            return sum(1 for _ in reader)
    except (OSError, UnicodeError, csv.Error) as error:
        raise AuditError(f"cannot read raw CSV {path}: {error}") from error


def portable(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise AuditError(f"evidence path escaped root: {path}") from error
    return relative.as_posix()


def stable_contract(summary: Mapping[str, Any]) -> dict[str, Any]:
    keys = (
        "arm_count",
        "arm_order",
        "commands",
        "environment_overrides",
        "executable_sha256",
        "parser_inclusive",
        "reference_arm",
        "repeats",
        "schedule",
        "schedule_binding",
        "schedule_sha256",
        "speedup_direction",
        "timeout_s",
        "timing_basis",
        "timing_scope",
    )
    missing = [key for key in keys if key not in summary]
    if missing:
        raise AuditError(f"summary lacks stable contract fields: {missing}")
    return {key: summary[key] for key in keys}


def aggregate_paths(
    paths: Sequence[Mapping[str, Any]], arms: Sequence[str]
) -> dict[str, Any]:
    reference = arms[0]
    common = [
        path
        for path in paths
        if all(path["arms"][arm]["covered"] is True for arm in arms)
    ]
    reference_times = [
        float(path["arms"][reference]["median_time_s"]) for path in common
    ]
    reference_total = math.fsum(reference_times)
    arm_results: dict[str, Any] = {}
    for arm in arms:
        covered = [path for path in paths if path["arms"][arm]["covered"] is True]
        times = [float(path["arms"][arm]["median_time_s"]) for path in common]
        ratios = [
            baseline / current
            for baseline, current in zip(reference_times, times)
            if baseline > 0 and current > 0
        ]
        gains = [
            path["relative_path"]
            for path in paths
            if path["arms"][arm]["covered"] is True
            and path["arms"][reference]["covered"] is not True
        ]
        losses = [
            path["relative_path"]
            for path in paths
            if path["arms"][reference]["covered"] is True
            and path["arms"][arm]["covered"] is not True
        ]
        total = math.fsum(times)
        arm_results[arm] = {
            "covered_paths": len(covered),
            "coverage": len(covered) / len(paths),
            "coverage_by_status": dict(
                sorted(Counter(path["expected_status"] for path in covered).items())
            ),
            "coverage_delta_vs_reference": len(covered)
            - sum(path["arms"][reference]["covered"] is True for path in paths),
            "gains_vs_reference": gains,
            "losses_vs_reference": losses,
            "common_total_time_s": total,
            "common_aggregate_speedup_vs_reference": (
                reference_total / total if common and total > 0 else None
            ),
            "common_geometric_speedup_vs_reference": (
                math.exp(math.fsum(math.log(ratio) for ratio in ratios) / len(ratios))
                if common and len(ratios) == len(common)
                else None
            ),
            "wins_vs_reference": sum(
                current < baseline
                for baseline, current in zip(reference_times, times)
            ),
            "losses_in_time_vs_reference": sum(
                baseline < current
                for baseline, current in zip(reference_times, times)
            ),
            "ties_vs_reference": sum(
                baseline == current
                for baseline, current in zip(reference_times, times)
            ),
        }
    return {
        "arms": arm_results,
        "common_correct": len(common),
        "common_correct_paths": [path["relative_path"] for path in common],
    }


def audit(root: Path, shard_count: int) -> dict[str, Any]:
    if shard_count < 1:
        raise AuditError("shard count must be positive")
    root = root.resolve(strict=True)
    selection_path = root / "selection-source.jsonl"
    manifest_path = root / "manifest.jsonl"
    task_path = root / "run_staged_qg7_matrix_task.sh"
    sbatch_path = root / "euf_viper_staged_qg7_matrix.sbatch"
    for path, context in (
        (selection_path, "selection"),
        (manifest_path, "manifest"),
        (task_path, "task script"),
        (sbatch_path, "sbatch script"),
    ):
        if not path.is_file() or path.is_symlink():
            raise AuditError(f"missing regular {context}: {path}")

    selection_hash = sha256_file(selection_path)
    manifest_hash = sha256_file(manifest_path)
    task_hash = sha256_file(task_path)
    sbatch_hash = sha256_file(sbatch_path)
    selection_rows = load_jsonl(selection_path, "selection")
    manifest_rows = load_jsonl(manifest_path, "rebased manifest")
    identities = verify_manifest_pair(selection_rows, manifest_rows)

    contract: dict[str, Any] | None = None
    control: dict[str, str] | None = None
    paths_by_name: dict[str, dict[str, Any]] = {}
    artifacts: list[dict[str, Any]] = []
    accounting: Counter[str] = Counter()
    measured_runs = 0

    for index in range(shard_count):
        padded = f"{index:04d}"
        shard_path = root / "shards" / f"shard-{padded}.jsonl"
        result_root = root / "results" / f"shard-{padded}"
        receipt_path = result_root / "receipt.tsv"
        summary_path = result_root / "summary.json"
        raw_path = result_root / "raw.csv"
        resource_path = result_root / "resource-usage.json"
        toolchain_path = result_root / "toolchain.tsv"
        receipt = read_receipt(receipt_path)
        expected_values = {
            "status": "complete",
            "array_task_id": str(index),
            "selection_sha256": selection_hash,
            "manifest_sha256": manifest_hash,
            "task_script_sha256": task_hash,
            "sbatch_script_sha256": sbatch_hash,
            "affinity_cpus": "1",
            "task_exit_code": "0",
        }
        for key, expected in expected_values.items():
            if receipt.get(key) != expected:
                raise AuditError(f"shard {index} receipt {key} drifted")
        if "AMD EPYC 9654" not in receipt.get("cpu_model", ""):
            raise AuditError(f"shard {index} CPU model drifted")

        current_control = {
            key: receipt[key]
            for key in (
                "array_job_id",
                "orchestration_revision",
                "runner_sha256",
                "solver_sha256",
                "toolchain_sha256",
            )
        }
        if "mode" in receipt:
            current_control["mode"] = receipt["mode"]
        if control is None:
            control = current_control
        elif current_control != control:
            raise AuditError(f"shard {index} control receipt differs")

        verify_hash(shard_path, receipt["shard_sha256"], f"shard {index} manifest")
        verify_hash(toolchain_path, receipt["toolchain_sha256"], f"shard {index} toolchain")
        shard_rows = load_jsonl(shard_path, f"shard {index} manifest")
        expected_rows = manifest_rows[index::shard_count]
        if [row_identity(row, f"shard {index} row") for row in shard_rows] != [
            row_identity(row, f"expected shard {index} row") for row in expected_rows
        ]:
            raise AuditError(f"shard {index} is not the expected round-robin derivation")

        summary = load_json(summary_path, f"shard {index} summary")
        if summary.get("status") != "complete" or summary.get("benchmark") != (
            "multiarm_williams_command"
        ):
            raise AuditError(f"shard {index} summary is not complete multi-arm evidence")
        current_contract = stable_contract(summary)
        if contract is None:
            contract = current_contract
        elif current_contract != contract:
            raise AuditError(f"shard {index} benchmark contract differs")
        arms = current_contract["arm_order"]
        if type(arms) is not list or len(arms) < 2:
            raise AuditError("benchmark arm order is invalid")
        if any(value != receipt["solver_sha256"] for value in summary["executable_sha256"].values()):
            raise AuditError(f"shard {index} executable hash differs from receipt")
        runner_record = summary.get("artifacts", {}).get("tool_sources", {}).get("runner")
        if type(runner_record) is not dict or runner_record.get("sha256") != receipt["runner_sha256"]:
            raise AuditError(f"shard {index} runner hash differs from receipt")
        if summary.get("manifest_sha256") != receipt["shard_sha256"]:
            raise AuditError(f"shard {index} summary manifest hash drifted")
        if summary.get("manifest_order") != [row["relative_path"] for row in expected_rows]:
            raise AuditError(f"shard {index} summary order drifted")
        if summary.get("source_sha256") != {
            row["relative_path"]: row["sha256"] for row in expected_rows
        }:
            raise AuditError(f"shard {index} source hashes drifted")
        if summary.get("instances") != len(expected_rows):
            raise AuditError(f"shard {index} instance count drifted")
        expected_runs = (
            len(expected_rows) * int(summary["arm_count"]) * int(summary["repeats"])
        )
        if summary.get("measured_runs") != expected_runs:
            raise AuditError(f"shard {index} measured run count drifted")
        results_record = summary.get("artifacts", {}).get("results_csv")
        if type(results_record) is not dict:
            raise AuditError(f"shard {index} summary lacks raw CSV metadata")
        verify_hash(raw_path, str(results_record.get("sha256")), f"shard {index} raw CSV")
        if read_csv_count(raw_path) != expected_runs:
            raise AuditError(f"shard {index} raw CSV row count drifted")
        if summary.get("accounting", {}).get("wrong_answers") != 0:
            raise AuditError(f"shard {index} contains wrong answers")
        if summary.get("accounting", {}).get("execution_errors") != 0:
            raise AuditError(f"shard {index} contains execution errors")

        shard_paths = summary.get("paths")
        if type(shard_paths) is not list or len(shard_paths) != len(expected_rows):
            raise AuditError(f"shard {index} path summaries are incomplete")
        for path_summary in shard_paths:
            if type(path_summary) is not dict:
                raise AuditError(f"shard {index} path summary is invalid")
            name = path_summary.get("relative_path")
            if type(name) is not str or name in paths_by_name:
                raise AuditError(f"shard {index} path summary is duplicated")
            paths_by_name[name] = path_summary
        accounting.update(
            {
                key: int(value)
                for key, value in summary.get("accounting", {}).items()
            }
        )
        measured_runs += expected_runs
        for required in (resource_path, summary_path, receipt_path):
            if not required.is_file() or required.is_symlink():
                raise AuditError(f"shard {index} evidence file is missing: {required}")
        artifacts.append(
            {
                "index": index,
                "receipt": portable(receipt_path, root),
                "receipt_sha256": sha256_file(receipt_path),
                "resource_usage_sha256": sha256_file(resource_path),
                "raw_sha256": sha256_file(raw_path),
                "shard_manifest_sha256": sha256_file(shard_path),
                "summary_sha256": sha256_file(summary_path),
                "toolchain_sha256": sha256_file(toolchain_path),
            }
        )

    assert contract is not None and control is not None
    ordered_names = [identity[0] for identity in identities]
    if set(paths_by_name) != set(ordered_names):
        raise AuditError("path summary union differs from the complete manifest")
    paths = [paths_by_name[name] for name in ordered_names]
    arms = list(contract["arm_order"])
    aggregate = aggregate_paths(paths, arms)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "audit_sha256": "",
        "instances": len(paths),
        "shards": shard_count,
        "measured_runs": measured_runs,
        "arm_order": arms,
        "reference_arm": arms[0],
        "control": control,
        "contract": contract,
        "accounting": dict(sorted(accounting.items())),
        "input_hashes": {
            "manifest_sha256": manifest_hash,
            "selection_sha256": selection_hash,
            "sbatch_script_sha256": sbatch_hash,
            "task_script_sha256": task_hash,
        },
        "shard_artifacts": artifacts,
        "paths": paths,
        **aggregate,
    }
    payload["audit_sha256"] = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return payload


def atomic_write_new(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise AuditError(f"refuse to replace audit output: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(dict(payload)))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o444)
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        payload = audit(args.root, args.shards)
        atomic_write_new(args.out, payload)
    except (AuditError, OSError, ValueError) as error:
        parser.exit(2, f"matrix audit failed: {error}\n")
    coverage = ", ".join(
        f"{arm}={payload['arms'][arm]['covered_paths']}/{payload['instances']}"
        for arm in payload["arm_order"]
    )
    print(
        f"audit={payload['audit_sha256']} coverage {coverage}; "
        f"wrong={payload['accounting'].get('wrong_answers', 0)}; "
        f"errors={payload['accounting'].get('execution_errors', 0)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
