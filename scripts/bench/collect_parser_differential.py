#!/usr/bin/env python3
"""Run fail-closed parse-only checks over an exact SMT-LIB manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import tempfile
import time
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path, PurePosixPath
from typing import Callable, Sequence


SCHEMA_VERSION = 2
PARSER_MODES = ("tree", "shadow", "stream")
DIAGNOSTIC_KEYS = (
    "parse_status",
    "parser_mode",
    "parser_route",
    "fallback_reason",
)
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
OUTPUT_LIMIT = 8192


class HarnessError(ValueError):
    """Raised for malformed inputs, incomplete evidence, or diagnostics."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_identity(path: Path) -> tuple[int, str]:
    size = 0
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def parse_diagnostic(output: str) -> dict[str, str]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        raise HarnessError("parse-check must emit exactly one non-empty stdout line")
    fields: dict[str, str] = {}
    for item in lines[0].split():
        if "=" not in item:
            raise HarnessError(f"malformed parse-check field: {item!r}")
        key, value = item.split("=", 1)
        if key in fields:
            raise HarnessError(f"duplicate parse-check field: {key}")
        fields[key] = value
    if tuple(fields) != DIAGNOSTIC_KEYS:
        raise HarnessError(
            f"parse-check fields must be {DIAGNOSTIC_KEYS}, observed {tuple(fields)}"
        )

    status = fields["parse_status"]
    mode = fields["parser_mode"]
    route = fields["parser_route"]
    fallback = fields["fallback_reason"]
    if status not in {"ok", "fallback"}:
        raise HarnessError(f"invalid parse status: {status!r}")
    if mode not in PARSER_MODES:
        raise HarnessError(f"invalid parser mode: {mode!r}")

    direct_route = {"tree": "tree", "shadow": "shadow-match", "stream": "stream"}
    if status == "ok":
        if route != direct_route[mode] or fallback != "none":
            raise HarnessError(
                "parse_status=ok requires the mode's direct route and "
                "fallback_reason=none"
            )
    elif mode == "tree" or route != "tree-fallback" or fallback == "none":
        raise HarnessError(
            "parse_status=fallback requires a non-tree mode, tree-fallback, "
            "and a reason"
        )
    return fields


def _manifest_sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise HarnessError(f"{context}: sha256 must be 64 lowercase hex digits")
    return value


def _manifest_bytes(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HarnessError(f"{context}: bytes must be a non-negative integer")
    return value


def _relative_path(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise HarnessError(f"{context}: relative_path must be a non-empty string")
    relative = PurePosixPath(value)
    if relative.is_absolute() or relative == PurePosixPath(".") or ".." in relative.parts:
        raise HarnessError(f"{context}: relative_path must stay below the benchmark root")
    if relative.as_posix() != value:
        raise HarnessError(f"{context}: relative_path must be normalized POSIX syntax")
    return value


def read_manifest(path: Path) -> list[dict]:
    entries: list[dict] = []
    seen: dict[str, int] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise HarnessError(f"cannot read manifest {path}: {error}") from error
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        context = f"{path}:{line_number}"
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as error:
            raise HarnessError(f"{context}: invalid JSON: {error.msg}") from error
        if not isinstance(entry, dict):
            raise HarnessError(f"{context}: row must be an object")
        relative_path = _relative_path(entry.get("relative_path"), context)
        if relative_path in seen:
            raise HarnessError(
                f"{context}: duplicate {relative_path!r}; first seen on line "
                f"{seen[relative_path]}"
            )
        seen[relative_path] = line_number
        expected_bytes = _manifest_bytes(entry.get("bytes"), context)
        expected_sha256 = _manifest_sha256(entry.get("sha256"), context)
        entries.append(
            {
                **entry,
                "relative_path": relative_path,
                "bytes": expected_bytes,
                "sha256": expected_sha256,
                "manifest_line": line_number,
            }
        )
    if not entries:
        raise HarnessError("manifest selection is empty")
    return entries


def resolve_input_path(entry: dict, benchmark_root: Path) -> Path:
    root = benchmark_root.expanduser().resolve()
    relative = PurePosixPath(entry["relative_path"])
    source = root.joinpath(*relative.parts).resolve()
    try:
        source.relative_to(root)
    except ValueError as error:
        raise HarnessError(
            f"resolved input escapes benchmark root: {entry['relative_path']!r}"
        ) from error
    return source


def failure_record(
    base: dict,
    kind: str,
    message: str,
    exit_code: int | None,
    *,
    wall_time_ns: int = 0,
    stdout: str | bytes | None = None,
    stderr: str | bytes | None = None,
) -> dict:
    record = {
        **base,
        "status": "timeout" if kind == "timeout" else "error",
        "failure_kind": kind,
        "message": message,
        "exit_code": exit_code,
        "wall_time_ns": wall_time_ns,
    }
    normalized_stdout = normalized_output(stdout)
    normalized_stderr = normalized_output(stderr)
    if normalized_stdout:
        record["stdout"] = normalized_stdout
    if normalized_stderr:
        record["stderr"] = normalized_stderr
    return record


def normalized_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode(encoding="utf-8", errors="replace")
    value = value.strip()
    if len(value) <= OUTPUT_LIMIT:
        return value
    return value[:OUTPUT_LIMIT] + "\n...[truncated]"


def _base_record(
    entry: dict,
    source: Path,
    candidate_parser_mode: str,
) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "id": entry.get("id", entry["manifest_line"]),
        "manifest_line": entry["manifest_line"],
        "relative_path": entry["relative_path"],
        "resolved_path": str(source),
        "expected_status": entry.get("status", "unknown"),
        "candidate_parser_mode": candidate_parser_mode,
        "source_expected_bytes": entry["bytes"],
        "source_expected_sha256": entry["sha256"],
    }


def run_entry(
    entry: dict,
    manifest: Path,
    binary: Path,
    candidate_parser_mode: str,
    timeout_s: float,
    benchmark_root: Path,
) -> dict:
    del manifest  # The explicit benchmark root owns relative-path resolution.
    try:
        source = resolve_input_path(entry, benchmark_root)
    except (HarnessError, OSError, RuntimeError) as error:
        unresolved = benchmark_root.joinpath(*PurePosixPath(entry["relative_path"]).parts)
        base = _base_record(entry, unresolved, candidate_parser_mode)
        base["corpus_verified"] = False
        return failure_record(base, "path_error", str(error), 66)

    base = _base_record(entry, source, candidate_parser_mode)
    if not source.is_file():
        base["corpus_verified"] = False
        return failure_record(base, "missing_input", f"missing input: {source}", 66)
    try:
        actual_bytes, actual_sha256 = file_identity(source)
    except OSError as error:
        base["corpus_verified"] = False
        return failure_record(
            base,
            "input_read_error",
            f"cannot read input for verification: {error}",
            66,
        )

    base.update(
        {
            "source_actual_bytes": actual_bytes,
            "source_actual_sha256": actual_sha256,
        }
    )
    mismatches = []
    if actual_bytes != entry["bytes"]:
        mismatches.append(f"bytes expected {entry['bytes']} actual {actual_bytes}")
    if actual_sha256 != entry["sha256"]:
        mismatches.append(
            f"sha256 expected {entry['sha256']} actual {actual_sha256}"
        )
    if mismatches:
        base["corpus_verified"] = False
        return failure_record(
            base,
            "source_identity_mismatch",
            "; ".join(mismatches),
            65,
        )
    base["corpus_verified"] = True

    environment = os.environ.copy()
    environment.pop("EUF_VIPER_PARSER", None)
    environment["EUF_VIPER_PARSER_MODE"] = candidate_parser_mode
    started = time.monotonic_ns()
    try:
        process = subprocess.run(
            [str(binary), "parse-check", str(source)],
            env=environment,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        return failure_record(
            base,
            "timeout",
            f"parse-check exceeded timeout of {timeout_s:g}s",
            124,
            wall_time_ns=time.monotonic_ns() - started,
            stdout=error.stdout,
            stderr=error.stderr,
        )
    except OSError as error:
        return failure_record(
            base,
            "spawn_error",
            f"cannot execute parse-check: {error}",
            None,
            wall_time_ns=time.monotonic_ns() - started,
            stderr=str(error),
        )

    wall_time_ns = time.monotonic_ns() - started
    if process.returncode != 0:
        stderr = normalized_output(process.stderr)
        return failure_record(
            base,
            "parse_error",
            stderr or f"parse-check exited {process.returncode}",
            process.returncode,
            wall_time_ns=wall_time_ns,
            stdout=process.stdout,
            stderr=process.stderr,
        )
    try:
        diagnostic = parse_diagnostic(process.stdout)
    except HarnessError as error:
        return failure_record(
            base,
            "diagnostic_error",
            str(error),
            65,
            wall_time_ns=wall_time_ns,
            stdout=process.stdout,
            stderr=process.stderr,
        )
    if diagnostic["parser_mode"] != candidate_parser_mode:
        return failure_record(
            base,
            "mode_mismatch",
            "parse-check reported "
            f"{diagnostic['parser_mode']!r}, expected {candidate_parser_mode!r}",
            65,
            wall_time_ns=wall_time_ns,
            stderr=process.stderr,
        )
    return {
        **base,
        "status": "ok",
        "exit_code": 0,
        "wall_time_ns": wall_time_ns,
        **diagnostic,
    }


def summarize(
    records: Sequence[dict],
    candidate_parser_mode: str,
    *,
    expected_instances: int | None = None,
    max_fallbacks: int = 0,
    fallback_limit_explicit: bool = False,
) -> dict:
    if expected_instances is None:
        expected_instances = len(records)
    successful = [record for record in records if record["status"] == "ok"]
    failures = [record for record in records if record["status"] != "ok"]
    routes = Counter(record["parser_route"] for record in successful)
    fallbacks = routes["tree-fallback"]
    direct_parses = len(successful) - fallbacks
    unique_paths = len({record["relative_path"] for record in records})
    row_count_verified = len(records) == expected_instances
    unique_paths_verified = unique_paths == len(records)
    fallback_gate_passed = fallbacks <= max_fallbacks
    direct_route_gate_passed = candidate_parser_mode == "tree" or direct_parses > 0
    corpus_verified = sum(record.get("corpus_verified") is True for record in records)
    corpus_verification_failed = sum(
        record.get("corpus_verified") is False for record in records
    )
    gate_passed = (
        row_count_verified
        and unique_paths_verified
        and len(successful) == expected_instances
        and corpus_verified == expected_instances
        and fallback_gate_passed
        and direct_route_gate_passed
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_parser_mode": candidate_parser_mode,
        "expected_instances": expected_instances,
        "instances": len(records),
        "successful": len(successful),
        "direct_parses": direct_parses,
        "direct_shadow_matches": routes["shadow-match"],
        "direct_stream_parses": routes["stream"],
        "direct_tree_parses": routes["tree"],
        "fallbacks": fallbacks,
        "tree_fallbacks": fallbacks,
        "errors": sum(record["status"] == "error" for record in failures),
        "timeouts": sum(record["status"] == "timeout" for record in failures),
        "routes": dict(sorted(routes.items())),
        "fallback_reasons": dict(
            sorted(
                Counter(
                    record["fallback_reason"]
                    for record in successful
                    if record["parse_status"] == "fallback"
                ).items()
            )
        ),
        "corpus_verification": {
            "completed": corpus_verified + corpus_verification_failed,
            "verified": corpus_verified,
            "failed": corpus_verification_failed,
            "pending": expected_instances
            - corpus_verified
            - corpus_verification_failed,
        },
        "evidence_integrity": {
            "row_count_verified": row_count_verified,
            "unique_paths_verified": unique_paths_verified,
            "unique_paths": unique_paths,
        },
        "fallback_gate": {
            "explicit_limit": fallback_limit_explicit,
            "max_fallbacks": max_fallbacks,
            "observed_fallbacks": fallbacks,
            "direct_route_required": candidate_parser_mode != "tree",
            "direct_route_observed": direct_parses > 0,
            "passed": fallback_gate_passed and direct_route_gate_passed,
        },
        "gate_passed": gate_passed,
        "failure_examples": [
            {
                "relative_path": record["relative_path"],
                "failure_kind": record["failure_kind"],
                "message": record["message"],
            }
            for record in failures[:25]
        ],
    }


def atomic_write_jsonl(path: Path, records: Sequence[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            for record in records:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


Checkpoint = Callable[[Sequence[dict], int, int], None]


def _internal_failure_record(
    entry: dict,
    benchmark_root: Path,
    candidate_parser_mode: str,
    error: Exception,
) -> dict:
    source = benchmark_root.joinpath(*PurePosixPath(entry["relative_path"]).parts)
    base = _base_record(entry, source, candidate_parser_mode)
    base["corpus_verified"] = False
    return failure_record(
        base,
        "internal_error",
        f"unhandled collector error: {type(error).__name__}: {error}",
        70,
    )


def collect_manifest(
    manifest: Path,
    binary: Path,
    candidate_parser_mode: str,
    timeout_s: float,
    jobs: int,
    benchmark_root: Path,
    *,
    entries: Sequence[dict] | None = None,
    checkpoint: Checkpoint | None = None,
    checkpoint_every: int = 25,
) -> tuple[list[dict], dict]:
    if not math.isfinite(timeout_s) or timeout_s <= 0:
        raise HarnessError("timeout must be a finite number greater than zero")
    if jobs < 1:
        raise HarnessError("jobs must be at least one")
    if checkpoint_every < 1:
        raise HarnessError("checkpoint_every must be at least one")
    selected = list(entries) if entries is not None else read_manifest(manifest)
    records: list[dict | None] = [None] * len(selected)

    def run_one(entry: dict) -> dict:
        return run_entry(
            entry,
            manifest,
            binary,
            candidate_parser_mode,
            timeout_s,
            benchmark_root,
        )

    futures: dict[Future[dict], int] = {}
    executor = ThreadPoolExecutor(max_workers=jobs)
    interrupted = True
    try:
        futures = {
            executor.submit(run_one, entry): index
            for index, entry in enumerate(selected)
        }
        completed = 0
        for future in as_completed(futures):
            index = futures[future]
            try:
                record = future.result()
            except Exception as error:  # Preserve a row even for a collector bug.
                record = _internal_failure_record(
                    selected[index], benchmark_root, candidate_parser_mode, error
                )
            records[index] = record
            completed += 1
            if checkpoint is not None and (
                completed % checkpoint_every == 0 or completed == len(selected)
            ):
                checkpoint(
                    [record for record in records if record is not None],
                    completed,
                    len(selected),
                )
        interrupted = False
    finally:
        executor.shutdown(wait=not interrupted, cancel_futures=interrupted)

    complete_records = [record for record in records if record is not None]
    validate_complete_records(selected, complete_records)
    return complete_records, summarize(complete_records, candidate_parser_mode)


def validate_complete_records(entries: Sequence[dict], records: Sequence[dict]) -> None:
    if len(records) != len(entries):
        raise HarnessError(
            f"incomplete evidence: expected {len(entries)} rows, observed {len(records)}"
        )
    observed_paths = [record.get("relative_path") for record in records]
    if len(set(observed_paths)) != len(observed_paths):
        raise HarnessError("evidence contains duplicate relative_path values")
    expected_paths = [entry["relative_path"] for entry in entries]
    if observed_paths != expected_paths:
        raise HarnessError("evidence paths or ordering do not match the manifest")


def _sha256_argument(value: str) -> str:
    if SHA256_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("must be 64 lowercase hex digits")
    return value


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _nonnegative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def _campaign_summary(
    records: Sequence[dict],
    *,
    candidate_parser_mode: str,
    expected_instances: int,
    max_fallbacks: int,
    fallback_limit_explicit: bool,
    campaign_status: str,
    manifest: Path,
    manifest_sha256: str,
    benchmark_root: Path,
    binary: Path,
    expected_binary_sha256: str,
    binary_sha256: str,
) -> dict:
    summary = summarize(
        records,
        candidate_parser_mode,
        expected_instances=expected_instances,
        max_fallbacks=max_fallbacks,
        fallback_limit_explicit=fallback_limit_explicit,
    )
    summary.update(
        {
            "campaign_status": campaign_status,
            "manifest": str(manifest),
            "manifest_sha256": manifest_sha256,
            "benchmark_root": str(benchmark_root),
            "binary": str(binary),
            "expected_binary_sha256": expected_binary_sha256,
            "binary_sha256": binary_sha256,
            "provenance": {
                "manifest": {
                    "path": str(manifest),
                    "sha256": manifest_sha256,
                    "expected_instances": expected_instances,
                },
                "corpus": {"benchmark_root": str(benchmark_root)},
                "binary": {
                    "path": str(binary),
                    "expected_sha256": expected_binary_sha256,
                    "actual_sha256": binary_sha256,
                    "sha256_verified": binary_sha256 == expected_binary_sha256,
                },
            },
        }
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run exact tree/shadow/stream parse checks over a JSONL manifest."
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--expected-binary-sha256", type=_sha256_argument, required=True)
    parser.add_argument("--expected-instances", type=_positive_int, required=True)
    parser.add_argument(
        "--candidate-parser-mode",
        choices=PARSER_MODES,
        required=True,
    )
    parser.add_argument(
        "--benchmark-root",
        type=Path,
        required=True,
        help="the exact root passed to make_manifest.py",
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--jobs", type=_positive_int, default=1)
    parser.add_argument(
        "--max-fallbacks",
        type=_nonnegative_int,
        help="explicit fallback allowance; omitted means zero",
    )
    parser.add_argument("--checkpoint-every", type=_positive_int, default=25)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--progress", type=Path, required=True)
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a finite number greater than zero")

    manifest = args.manifest.expanduser().resolve()
    binary = args.binary.expanduser().resolve()
    benchmark_root = args.benchmark_root.expanduser().resolve()
    if not manifest.is_file():
        parser.error(f"missing manifest: {manifest}")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error(f"binary must be an executable file: {binary}")
    if not benchmark_root.is_dir():
        parser.error(f"benchmark root must be a directory: {benchmark_root}")
    outputs = {args.out.resolve(), args.summary.resolve(), args.progress.resolve()}
    if len(outputs) != 3 or manifest in outputs or binary in outputs:
        parser.error("manifest, binary, output, summary, and progress paths must differ")

    try:
        entries = read_manifest(manifest)
        manifest_sha256 = sha256_file(manifest)
        binary_sha256 = sha256_file(binary)
    except (HarnessError, OSError) as error:
        parser.error(str(error))
    if len(entries) != args.expected_instances:
        parser.error(
            "manifest instance count mismatch: "
            f"expected {args.expected_instances}, actual {len(entries)}"
        )
    if binary_sha256 != args.expected_binary_sha256:
        parser.error(
            "binary SHA256 mismatch: "
            f"expected {args.expected_binary_sha256}, actual {binary_sha256}"
        )

    fallback_limit_explicit = args.max_fallbacks is not None
    max_fallbacks = args.max_fallbacks if args.max_fallbacks is not None else 0
    if max_fallbacks >= args.expected_instances:
        parser.error(
            "--max-fallbacks must be less than --expected-instances so an "
            "all-fallback campaign cannot pass"
        )

    def write_checkpoint(
        records: Sequence[dict], completed: int, expected: int
    ) -> None:
        summary = _campaign_summary(
            records,
            candidate_parser_mode=args.candidate_parser_mode,
            expected_instances=args.expected_instances,
            max_fallbacks=max_fallbacks,
            fallback_limit_explicit=fallback_limit_explicit,
            campaign_status="running",
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            benchmark_root=benchmark_root,
            binary=binary,
            expected_binary_sha256=args.expected_binary_sha256,
            binary_sha256=binary_sha256,
        )
        atomic_write_jsonl(args.out, records)
        atomic_write_json(args.summary, summary)
        atomic_write_json(
            args.progress,
            {
                "schema_version": SCHEMA_VERSION,
                "campaign_status": "running",
                "completed_instances": completed,
                "expected_instances": expected,
                "remaining_instances": expected - completed,
                "manifest_sha256": manifest_sha256,
                "binary_sha256": binary_sha256,
                "updated_at_unix_ns": time.time_ns(),
            },
        )

    write_checkpoint([], 0, args.expected_instances)
    try:
        records, _ = collect_manifest(
            manifest,
            binary,
            args.candidate_parser_mode,
            args.timeout,
            args.jobs,
            benchmark_root,
            entries=entries,
            checkpoint=write_checkpoint,
            checkpoint_every=args.checkpoint_every,
        )
        validate_complete_records(entries, records)
    except HarnessError as error:
        parser.error(str(error))

    summary = _campaign_summary(
        records,
        candidate_parser_mode=args.candidate_parser_mode,
        expected_instances=args.expected_instances,
        max_fallbacks=max_fallbacks,
        fallback_limit_explicit=fallback_limit_explicit,
        campaign_status="complete",
        manifest=manifest,
        manifest_sha256=manifest_sha256,
        benchmark_root=benchmark_root,
        binary=binary,
        expected_binary_sha256=args.expected_binary_sha256,
        binary_sha256=binary_sha256,
    )
    atomic_write_jsonl(args.out, records)
    atomic_write_json(args.summary, summary)
    atomic_write_json(
        args.progress,
        {
            "schema_version": SCHEMA_VERSION,
            "campaign_status": "complete",
            "completed_instances": len(records),
            "expected_instances": args.expected_instances,
            "remaining_instances": 0,
            "manifest_sha256": manifest_sha256,
            "binary_sha256": binary_sha256,
            "gate_passed": summary["gate_passed"],
            "updated_at_unix_ns": time.time_ns(),
        },
    )
    print(
        f"parser_mode={args.candidate_parser_mode} "
        f"instances={summary['instances']} successful={summary['successful']} "
        f"direct={summary['direct_parses']} fallbacks={summary['fallbacks']} "
        f"errors={summary['errors']} timeouts={summary['timeouts']} "
        f"gate_passed={str(summary['gate_passed']).lower()}"
    )
    return 0 if summary["gate_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
