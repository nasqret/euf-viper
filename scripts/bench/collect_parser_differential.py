#!/usr/bin/env python3
"""Run parse-only euf-viper differential checks over an SMT-LIB manifest."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Sequence


PARSER_MODES = ("tree", "shadow", "stream")
DIAGNOSTIC_KEYS = (
    "parse_status",
    "parser_mode",
    "parser_route",
    "fallback_reason",
)


class HarnessError(ValueError):
    """Raised for malformed manifests or parser diagnostics."""


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
    allowed_routes = {
        "tree": {"tree"},
        "shadow": {"shadow-match", "tree-fallback"},
        "stream": {"stream", "tree-fallback"},
    }
    if route not in allowed_routes[mode]:
        raise HarnessError(f"invalid route {route!r} for parser mode {mode!r}")
    if status == "ok" and fallback != "none":
        raise HarnessError("successful direct parse must use fallback_reason=none")
    if status == "fallback" and (
        route != "tree-fallback" or fallback == "none"
    ):
        raise HarnessError("fallback parse requires tree-fallback and a reason")
    return fields


def read_manifest(path: Path) -> list[dict]:
    entries = []
    seen = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise HarnessError(f"cannot read manifest {path}: {error}") from error
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as error:
            raise HarnessError(f"{path}:{line_number}: invalid JSON: {error}") from error
        if not isinstance(entry, dict):
            raise HarnessError(f"{path}:{line_number}: row must be an object")
        relative_path = entry.get("relative_path")
        if not isinstance(relative_path, str) or not relative_path:
            raise HarnessError(
                f"{path}:{line_number}: relative_path must be a non-empty string"
            )
        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise HarnessError(
                f"{path}:{line_number}: relative_path must stay below the corpus root"
            )
        if relative_path in seen:
            raise HarnessError(f"{path}:{line_number}: duplicate {relative_path!r}")
        seen.add(relative_path)
        entries.append({**entry, "manifest_line": line_number})
    if not entries:
        raise HarnessError("manifest selection is empty")
    return entries


def resolve_input_path(
    entry: dict, manifest: Path, benchmark_root: Path | None
) -> Path:
    if benchmark_root is not None:
        return benchmark_root.joinpath(*Path(entry["relative_path"]).parts).resolve()
    configured = entry.get("path")
    if isinstance(configured, str) and configured:
        path = Path(configured)
        return path if path.is_absolute() else (manifest.parent / path).resolve()
    return manifest.parent.joinpath(*Path(entry["relative_path"]).parts).resolve()


def failure_record(base: dict, kind: str, message: str, exit_code: int) -> dict:
    return {
        **base,
        "status": "error" if kind != "timeout" else "timeout",
        "failure_kind": kind,
        "message": message,
        "exit_code": exit_code,
    }


def normalized_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace").strip()
    return value.strip()


def run_entry(
    entry: dict,
    manifest: Path,
    binary: Path,
    candidate_parser_mode: str,
    timeout_s: float,
    benchmark_root: Path | None,
) -> dict:
    source = resolve_input_path(entry, manifest, benchmark_root)
    base = {
        "schema_version": 1,
        "id": entry.get("id", entry["manifest_line"]),
        "manifest_line": entry["manifest_line"],
        "relative_path": entry["relative_path"],
        "resolved_path": str(source),
        "expected_status": entry.get("status", "unknown"),
        "candidate_parser_mode": candidate_parser_mode,
    }
    if not source.is_file():
        return failure_record(base, "missing_input", f"missing input: {source}", 66)

    environment = os.environ.copy()
    environment.pop("EUF_VIPER_PARSER", None)
    environment["EUF_VIPER_PARSER_MODE"] = candidate_parser_mode
    started = time.monotonic_ns()
    try:
        process = subprocess.run(
            [str(binary), "parse-check", str(source)],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        return {
            **failure_record(base, "timeout", "parse-check timed out", 124),
            "wall_time_ns": time.monotonic_ns() - started,
            "stderr": normalized_output(error.stderr),
        }

    wall_time_ns = time.monotonic_ns() - started
    stderr = process.stderr.strip()
    if process.returncode != 0:
        return {
            **failure_record(
                base,
                "parse_error",
                stderr or f"parse-check exited {process.returncode}",
                process.returncode,
            ),
            "wall_time_ns": wall_time_ns,
            "stderr": stderr,
        }
    try:
        diagnostic = parse_diagnostic(process.stdout)
    except HarnessError as error:
        return {
            **failure_record(base, "diagnostic_error", str(error), 65),
            "wall_time_ns": wall_time_ns,
            "stderr": stderr,
        }
    if diagnostic["parser_mode"] != candidate_parser_mode:
        return {
            **failure_record(
                base,
                "mode_mismatch",
                "parse-check reported "
                f"{diagnostic['parser_mode']!r}, expected {candidate_parser_mode!r}",
                65,
            ),
            "wall_time_ns": wall_time_ns,
            "stderr": stderr,
        }
    return {
        **base,
        "status": "ok",
        "exit_code": 0,
        "wall_time_ns": wall_time_ns,
        **diagnostic,
    }


def summarize(records: Sequence[dict], candidate_parser_mode: str) -> dict:
    successful = [record for record in records if record["status"] == "ok"]
    failures = [record for record in records if record["status"] != "ok"]
    return {
        "schema_version": 1,
        "candidate_parser_mode": candidate_parser_mode,
        "instances": len(records),
        "successful": len(successful),
        "fallbacks": sum(
            record.get("parse_status") == "fallback" for record in successful
        ),
        "errors": sum(record["status"] == "error" for record in failures),
        "timeouts": sum(record["status"] == "timeout" for record in failures),
        "routes": dict(
            sorted(Counter(record["parser_route"] for record in successful).items())
        ),
        "fallback_reasons": dict(
            sorted(
                Counter(
                    record["fallback_reason"]
                    for record in successful
                    if record["fallback_reason"] != "none"
                ).items()
            )
        ),
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
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    os.replace(temporary, path)


def atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, path)


def collect_manifest(
    manifest: Path,
    binary: Path,
    candidate_parser_mode: str,
    timeout_s: float,
    jobs: int,
    benchmark_root: Path | None,
) -> tuple[list[dict], dict]:
    entries = read_manifest(manifest)

    def run_one(entry: dict) -> dict:
        return run_entry(
            entry,
            manifest,
            binary,
            candidate_parser_mode,
            timeout_s,
            benchmark_root,
        )

    with ThreadPoolExecutor(max_workers=jobs) as executor:
        records = list(executor.map(run_one, entries))
    return records, summarize(records, candidate_parser_mode)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run parse-only tree/shadow/stream checks over a JSONL manifest."
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--candidate-parser-mode",
        choices=PARSER_MODES,
        required=True,
    )
    parser.add_argument("--benchmark-root", type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.jobs <= 0:
        parser.error("--jobs must be positive")
    if not args.binary.is_file():
        parser.error(f"missing binary: {args.binary}")
    resolved_outputs = {args.out.resolve(), args.summary.resolve()}
    if len(resolved_outputs) != 2 or args.manifest.resolve() in resolved_outputs:
        parser.error("manifest, output, and summary paths must be distinct")

    try:
        records, summary = collect_manifest(
            args.manifest,
            args.binary.resolve(),
            args.candidate_parser_mode,
            args.timeout,
            args.jobs,
            args.benchmark_root,
        )
    except HarnessError as error:
        parser.error(str(error))
    summary.update(
        {
            "manifest": str(args.manifest),
            "binary": str(args.binary),
        }
    )
    atomic_write_jsonl(args.out, records)
    atomic_write_json(args.summary, summary)
    print(
        f"parser_mode={args.candidate_parser_mode} "
        f"instances={summary['instances']} successful={summary['successful']} "
        f"fallbacks={summary['fallbacks']} errors={summary['errors']} "
        f"timeouts={summary['timeouts']}"
    )
    return 0 if summary["successful"] == summary["instances"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
