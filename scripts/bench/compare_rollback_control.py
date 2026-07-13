#!/usr/bin/env python3
"""Run a same-binary ABBA control against the CaDiCaL rollback backend."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping


JOURNAL_SCHEMA = "rollback-control-journal-v1"
SUMMARY_SCHEMA = "rollback-control-summary-v1"
DECISIVE_RESULTS = {"sat", "unsat"}
CONTROL_CLASSES = {"target", "anti-target"}
LABELS = ("baseline", "candidate")
COMPARISONS = ("current", "model-cuts", "dynamic")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
PROFILE_RE = re.compile(
    r"^profile_([A-Za-z0-9_]+)_ns=([0-9]+) count=([0-9]+)$"
)
STAT_RE = re.compile(r"^([a-z][a-z0-9_]*)=([0-9]+)$")

# These are three explicit complete-model controls, not aliases for the candidate.
BASELINE_CONFIGS: dict[str, dict[str, str]] = {
    "current": {
        "EUF_VIPER_BACKEND": "cadical-refine",
        "EUF_VIPER_FULL_ACKERMANN": "off",
        "EUF_VIPER_REFINEMENT_MODE": "current",
    },
    "model-cuts": {
        "EUF_VIPER_BACKEND": "cadical-refine",
        "EUF_VIPER_FULL_ACKERMANN": "off",
        "EUF_VIPER_REFINEMENT_MODE": "model-cuts",
    },
    "dynamic": {
        "EUF_VIPER_BACKEND": "auto",
        "EUF_VIPER_FULL_ACKERMANN": "auto",
        "EUF_VIPER_REFINEMENT_MODE": "current",
    },
}
CANDIDATE_CONFIG = {"EUF_VIPER_BACKEND": "cadical-rollback"}

PLAN_KEYS = {
    "argv_template",
    "binary_path",
    "binary_sha256",
    "binary_size",
    "clean_environment_sha256",
    "comparison",
    "cpu_affinity",
    "environment_sha256",
    "host",
    "journal_schema",
    "labels",
    "manifest_path",
    "manifest_rows",
    "manifest_sha256",
    "order",
    "previous_record_sha256",
    "record_hash",
    "record_type",
    "removed_ambient_euf_viper",
    "repeats",
    "schema_version",
    "selected_rows",
    "shard",
    "solver_environment",
    "timeout_s",
}
OBSERVATION_KEYS = {
    "argv",
    "binary_sha256",
    "comparison",
    "control_class",
    "environment_sha256",
    "exit_code",
    "expected_status",
    "key",
    "label",
    "manifest_index",
    "order_slot",
    "outcome",
    "previous_record_sha256",
    "profile",
    "record_hash",
    "record_type",
    "relative_path",
    "repeat",
    "result",
    "result_token",
    "schema_version",
    "sequence",
    "source_bytes",
    "source_path",
    "source_sha256",
    "spawn_error",
    "stats",
    "stderr_bytes",
    "stderr_excerpt",
    "stderr_sha256",
    "stdout_bytes",
    "stdout_excerpt",
    "stdout_sha256",
    "timed_out",
    "wall_time_ns",
}


class CompareError(RuntimeError):
    """Raised when the control cannot produce a bound observation journal."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CompareError(f"duplicate JSON key {key!r}")
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
        raise CompareError(f"value is not canonical JSON: {error}") from error
    return (encoded + "\n").encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def record_hash(record: Mapping[str, Any]) -> str:
    unhashed = dict(record)
    unhashed.pop("record_hash", None)
    return sha256_bytes(canonical_bytes(unhashed))


def parse_json(line: str, context: str) -> dict[str, Any]:
    try:
        value = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, CompareError) as error:
        raise CompareError(f"{context}: invalid JSON: {error}") from error
    if type(value) is not dict:
        raise CompareError(f"{context}: record must be an object")
    return value


def load_manifest(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise CompareError(f"cannot read manifest {path}: {error}") from error
    if not text or not text.endswith("\n"):
        raise CompareError(f"manifest {path} is empty or lacks a final newline")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise CompareError(f"{path}:{line_number}: blank record")
        row = parse_json(line, f"{path}:{line_number}")
        for field in ("relative_path", "path", "sha256", "status", "control_class"):
            if type(row.get(field)) is not str or not row[field]:
                raise CompareError(f"{path}:{line_number}: invalid {field}")
        if row["relative_path"] in seen:
            raise CompareError(
                f"{path}:{line_number}: duplicate {row['relative_path']!r}"
            )
        if SHA256_RE.fullmatch(row["sha256"]) is None:
            raise CompareError(f"{path}:{line_number}: invalid source SHA-256")
        if row["status"] not in DECISIVE_RESULTS:
            raise CompareError(f"{path}:{line_number}: non-decisive expected status")
        if row["control_class"] not in CONTROL_CLASSES:
            raise CompareError(f"{path}:{line_number}: invalid control_class")
        if type(row.get("bytes")) is not int or row["bytes"] < 0:
            raise CompareError(f"{path}:{line_number}: invalid bytes")
        seen.add(row["relative_path"])
        rows.append(row)
    if not any(row["control_class"] == "target" for row in rows):
        raise CompareError("control manifest contains no targets")
    if not any(row["control_class"] == "anti-target" for row in rows):
        raise CompareError("control manifest contains no anti-targets")
    return rows


def resolve_source(
    row: Mapping[str, Any], manifest: Path, corpus_root: Path | None
) -> Path:
    configured = Path(row["path"])
    candidates: list[Path] = []
    if configured.is_absolute():
        candidates.append(configured)
    else:
        candidates.extend((Path.cwd() / configured, manifest.parent / configured))
    if corpus_root is not None:
        candidates.append(corpus_root / row["relative_path"])
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise CompareError(
        f"cannot resolve {row['relative_path']!r}; tried "
        + ", ".join(str(candidate) for candidate in candidates)
    )


def verify_source(row: Mapping[str, Any], source: Path) -> None:
    actual_bytes = source.stat().st_size
    if actual_bytes != row["bytes"]:
        raise CompareError(
            f"source byte drift for {row['relative_path']!r}: "
            f"expected {row['bytes']}, got {actual_bytes}"
        )
    actual_hash = sha256_file(source)
    if actual_hash != row["sha256"]:
        raise CompareError(
            f"source hash drift for {row['relative_path']!r}: "
            f"expected {row['sha256']}, got {actual_hash}"
        )


def solver_config(comparison: str, label: str) -> dict[str, str]:
    if comparison not in BASELINE_CONFIGS:
        raise CompareError(f"unknown comparison {comparison!r}")
    configured = BASELINE_CONFIGS[comparison] if label == "baseline" else CANDIDATE_CONFIG
    return {**configured, "EUF_VIPER_PROFILE": "1"}


def clean_environment(
    ambient: Mapping[str, str], configured: Mapping[str, str]
) -> tuple[dict[str, str], list[str]]:
    removed = sorted(key for key in ambient if key.startswith("EUF_VIPER_"))
    environment = {
        key: value for key, value in ambient.items() if not key.startswith("EUF_VIPER_")
    }
    environment.update(configured)
    environment["EUF_VIPER_PROFILE"] = "1"
    return environment, removed


def environment_hash(environment: Mapping[str, str]) -> str:
    return sha256_bytes(canonical_bytes(dict(sorted(environment.items()))))


def parse_cpu_affinity(value: str) -> list[int]:
    if not value:
        raise CompareError("expected CPU affinity cannot be empty")
    cpu_ids: list[int] = []
    for item in value.split(","):
        if not item or not item.isdecimal():
            raise CompareError(
                "expected CPU affinity must be a comma-separated list of CPU ids"
            )
        cpu_ids.append(int(item))
    if cpu_ids != sorted(set(cpu_ids)):
        raise CompareError("expected CPU affinity must be sorted and duplicate-free")
    return cpu_ids


def bind_cpu_affinity(
    *, expected_cpu_ids: list[int] | None, require_single_cpu: bool
) -> dict[str, Any]:
    get_affinity = getattr(os, "sched_getaffinity", None)
    if get_affinity is None:
        if expected_cpu_ids is not None or require_single_cpu:
            raise CompareError("this platform cannot verify CPU affinity")
        return {
            "cpu_ids": [],
            "expected_cpu_ids": None,
            "mechanism": "unavailable",
            "single_cpu_required": False,
        }
    try:
        cpu_ids = sorted(get_affinity(0))
    except OSError as error:
        raise CompareError(f"cannot read CPU affinity: {error}") from error
    if not cpu_ids:
        raise CompareError("sched_getaffinity returned an empty CPU set")
    if expected_cpu_ids is not None and cpu_ids != expected_cpu_ids:
        raise CompareError(
            f"CPU affinity mismatch: expected {expected_cpu_ids}, got {cpu_ids}"
        )
    if require_single_cpu and len(cpu_ids) != 1:
        raise CompareError(f"single-CPU execution required, got affinity {cpu_ids}")
    return {
        "cpu_ids": cpu_ids,
        "expected_cpu_ids": expected_cpu_ids,
        "mechanism": "sched_getaffinity",
        "single_cpu_required": require_single_cpu,
    }


def parse_telemetry(stderr: str) -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    """Accumulate repeated same-name profile phases and retain --stats values."""

    profile: dict[str, dict[str, int]] = {}
    stats: dict[str, int] = {}
    for line in stderr.splitlines():
        match = PROFILE_RE.fullmatch(line.strip())
        if match is not None:
            name, elapsed_text, count_text = match.groups()
            phase = profile.setdefault(name, {"elapsed_ns": 0, "count": 0})
            phase["elapsed_ns"] += int(elapsed_text)
            phase["count"] += int(count_text)
            continue
        match = STAT_RE.fullmatch(line.strip())
        if match is not None and not match.group(1).startswith("profile_"):
            stats[match.group(1)] = int(match.group(2))
    return dict(sorted(profile.items())), dict(sorted(stats.items()))


def result_token(stdout: str) -> str | None:
    lines = stdout.strip().splitlines()
    if not lines:
        return None
    token = lines[0].strip()
    return token if token in {"sat", "unsat", "unsupported"} else None


def classify_observation(
    *, expected_status: str, token: str | None, exit_code: int | None, timed_out: bool
) -> tuple[str, str]:
    if timed_out:
        return "timeout", "coverage_miss"
    if exit_code == 3:
        return "unsupported", "coverage_miss"
    if exit_code != 0:
        return token or "execution-error", "execution_error"
    if token in DECISIVE_RESULTS:
        return token, "correct" if token == expected_status else "wrong"
    return token or "malformed-output", "execution_error"


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.communicate(timeout=0.25)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.communicate()


def run_solver(
    *,
    binary: Path,
    source: Path,
    environment: Mapping[str, str],
    expected_status: str,
    timeout_s: float,
) -> dict[str, Any]:
    argv = [str(binary), "solve", "--stats", str(source)]
    start_ns = time.perf_counter_ns()
    timed_out = False
    spawn_error: str | None = None
    stdout_bytes = b""
    stderr_bytes = b""
    exit_code: int | None = None
    try:
        process = subprocess.Popen(
            argv,
            env=dict(environment),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout_bytes, stderr_bytes = process.communicate(timeout=timeout_s)
            exit_code = process.returncode
        except subprocess.TimeoutExpired as error:
            timed_out = True
            stdout_bytes = error.output or b""
            stderr_bytes = error.stderr or b""
            _terminate_process_group(process)
            exit_code = 124
    except OSError as error:
        spawn_error = str(error)
    wall_time_ns = max(1, time.perf_counter_ns() - start_ns)
    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    token = result_token(stdout)
    result, outcome = classify_observation(
        expected_status=expected_status,
        token=token,
        exit_code=exit_code,
        timed_out=timed_out,
    )
    profile, stats = parse_telemetry(stderr)
    return {
        "argv": argv,
        "exit_code": exit_code,
        "outcome": outcome,
        "profile": profile,
        "result": result,
        "result_token": token,
        "spawn_error": spawn_error,
        "stats": stats,
        "stderr_bytes": len(stderr_bytes),
        "stderr_excerpt": stderr[-4096:],
        "stderr_sha256": sha256_bytes(stderr_bytes),
        "stdout_bytes": len(stdout_bytes),
        "stdout_excerpt": stdout[:2048],
        "stdout_sha256": sha256_bytes(stdout_bytes),
        "timed_out": timed_out,
        "wall_time_ns": wall_time_ns,
    }


def abba_labels(repeat: int) -> tuple[str, str]:
    return LABELS if repeat % 2 == 0 else tuple(reversed(LABELS))


class JournalWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle: Any = None
        self.last_hash: str | None = None

    def __enter__(self) -> "JournalWriter":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.handle = self.path.open("xb")
        except FileExistsError as error:
            raise CompareError(f"refusing to overwrite journal {self.path}") from error
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.handle is not None:
            self.handle.close()
            self.handle = None

    def append(self, record: Mapping[str, Any]) -> dict[str, Any]:
        if self.handle is None:
            raise CompareError("journal is not open")
        complete = dict(record)
        complete["previous_record_sha256"] = self.last_hash
        complete["record_hash"] = record_hash(complete)
        payload = canonical_bytes(complete)
        self.handle.write(payload)
        self.handle.flush()
        os.fsync(self.handle.fileno())
        self.last_hash = complete["record_hash"]
        return complete


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise CompareError(f"refusing to overwrite summary {path}")
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


def make_plan(
    *,
    manifest: Path,
    manifest_sha256: str,
    manifest_rows: int,
    selected_rows: int,
    binary: Path,
    binary_sha256: str,
    comparison: str,
    cpu_affinity: Mapping[str, Any],
    timeout_s: float,
    repeats: int,
    shard_index: int,
    shard_count: int,
    environments: Mapping[str, Mapping[str, str]],
    configured: Mapping[str, Mapping[str, str]],
    removed: list[str],
) -> dict[str, Any]:
    return {
        "argv_template": [str(binary), "solve", "--stats", "{source}"],
        "binary_path": str(binary),
        "binary_sha256": binary_sha256,
        "binary_size": binary.stat().st_size,
        "clean_environment_sha256": environment_hash(
            {key: value for key, value in environments["baseline"].items() if not key.startswith("EUF_VIPER_")}
        ),
        "comparison": comparison,
        "cpu_affinity": dict(cpu_affinity),
        "environment_sha256": {
            label: environment_hash(environments[label]) for label in LABELS
        },
        "host": platform.node(),
        "journal_schema": JOURNAL_SCHEMA,
        "labels": list(LABELS),
        "manifest_path": str(manifest.resolve()),
        "manifest_rows": manifest_rows,
        "manifest_sha256": manifest_sha256,
        "order": "ABBA",
        "record_type": "plan",
        "removed_ambient_euf_viper": removed,
        "repeats": repeats,
        "schema_version": 1,
        "selected_rows": selected_rows,
        "shard": {
            "count": shard_count,
            "index": shard_index,
            "mechanism": "manifest-index-modulo",
        },
        "solver_environment": {
            label: dict(sorted(configured[label].items())) for label in LABELS
        },
        "timeout_s": timeout_s,
    }


def make_summary(
    *,
    plan: Mapping[str, Any],
    journal: Path,
    chain_head: str,
    observations: list[dict[str, Any]],
) -> dict[str, Any]:
    outcomes = {
        label: dict(
            sorted(
                Counter(
                    observation["outcome"]
                    for observation in observations
                    if observation["label"] == label
                ).items()
            )
        )
        for label in LABELS
    }
    result_counts = {
        label: dict(
            sorted(
                Counter(
                    observation["result"]
                    for observation in observations
                    if observation["label"] == label
                ).items()
            )
        )
        for label in LABELS
    }
    phase_totals: dict[str, dict[str, dict[str, int]]] = {}
    for label in LABELS:
        accumulated: dict[str, dict[str, int]] = defaultdict(
            lambda: {"elapsed_ns": 0, "count": 0}
        )
        for observation in observations:
            if observation["label"] != label:
                continue
            for name, phase in observation["profile"].items():
                accumulated[name]["elapsed_ns"] += phase["elapsed_ns"]
                accumulated[name]["count"] += phase["count"]
        phase_totals[label] = dict(sorted(accumulated.items()))
    payload: dict[str, Any] = {
        "binary_sha256": plan["binary_sha256"],
        "comparison": plan["comparison"],
        "cpu_affinity": plan["cpu_affinity"],
        "environment_sha256": plan["environment_sha256"],
        "expected_observations": plan["selected_rows"] * len(LABELS) * plan["repeats"],
        "journal_path": str(journal.resolve()),
        "journal_record_chain_head": chain_head,
        "journal_sha256": sha256_file(journal),
        "manifest_sha256": plan["manifest_sha256"],
        "observations": len(observations),
        "outcomes": outcomes,
        "phase_totals": phase_totals,
        "plan_record_hash": plan["record_hash"],
        "result_counts": result_counts,
        "schema_version": SUMMARY_SCHEMA,
        "shard": plan["shard"],
        "summary_sha256": "",
    }
    payload["summary_sha256"] = sha256_bytes(canonical_bytes(payload))
    return payload


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--comparison", choices=COMPARISONS, required=True)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--repeats", type=int, default=4)
    parser.add_argument(
        "--expected-cpu-affinity",
        help="sorted comma-separated CPU ids that sched_getaffinity(0) must report",
    )
    parser.add_argument(
        "--require-single-cpu",
        action="store_true",
        help="fail unless the runner is already bound to exactly one CPU",
    )
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    parser.add_argument("--corpus-root", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a positive finite number")
    if args.repeats < 2 or args.repeats % 2 != 0:
        parser.error("--repeats must be a positive even count (one or more ABBA blocks)")
    if args.shard_count < 1 or not 0 <= args.shard_index < args.shard_count:
        parser.error("require 0 <= --shard-index < --shard-count")
    if args.out.resolve() == args.summary.resolve():
        parser.error("--out and --summary must be different files")
    if args.out.exists() or args.summary.exists():
        parser.error("output artifacts already exist")
    try:
        binary = args.binary.resolve(strict=True)
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise CompareError(f"binary is not executable: {binary}")
        manifest_rows = load_manifest(args.manifest)
        expected_cpu_ids = (
            parse_cpu_affinity(args.expected_cpu_affinity)
            if args.expected_cpu_affinity is not None
            else None
        )
        cpu_affinity = bind_cpu_affinity(
            expected_cpu_ids=expected_cpu_ids,
            require_single_cpu=args.require_single_cpu,
        )
        manifest_sha256 = sha256_file(args.manifest)
        selected: list[tuple[int, dict[str, Any], Path]] = []
        for manifest_index, row in enumerate(manifest_rows):
            if manifest_index % args.shard_count != args.shard_index:
                continue
            source = resolve_source(row, args.manifest, args.corpus_root)
            verify_source(row, source)
            selected.append((manifest_index, row, source))

        configured = {
            label: solver_config(args.comparison, label) for label in LABELS
        }
        environments: dict[str, dict[str, str]] = {}
        removed: list[str] | None = None
        for label in LABELS:
            environment, removed_keys = clean_environment(os.environ, configured[label])
            environments[label] = environment
            if removed is None:
                removed = removed_keys
            elif removed != removed_keys:
                raise CompareError("ambient environment changed during setup")
        assert removed is not None
        binary_sha256 = sha256_file(binary)
        plan_template = make_plan(
            manifest=args.manifest,
            manifest_sha256=manifest_sha256,
            manifest_rows=len(manifest_rows),
            selected_rows=len(selected),
            binary=binary,
            binary_sha256=binary_sha256,
            comparison=args.comparison,
            cpu_affinity=cpu_affinity,
            timeout_s=args.timeout,
            repeats=args.repeats,
            shard_index=args.shard_index,
            shard_count=args.shard_count,
            environments=environments,
            configured=configured,
            removed=removed,
        )
        observations: list[dict[str, Any]] = []
        with JournalWriter(args.out) as journal:
            plan = journal.append(plan_template)
            sequence = 0
            for manifest_index, row, source in selected:
                for repeat in range(args.repeats):
                    for order_slot, label in enumerate(abba_labels(repeat)):
                        measured = run_solver(
                            binary=binary,
                            source=source,
                            environment=environments[label],
                            expected_status=row["status"],
                            timeout_s=args.timeout,
                        )
                        observation = journal.append(
                            {
                                **measured,
                                "binary_sha256": binary_sha256,
                                "comparison": args.comparison,
                                "control_class": row["control_class"],
                                "environment_sha256": environment_hash(
                                    environments[label]
                                ),
                                "expected_status": row["status"],
                                "key": {
                                    "comparison": args.comparison,
                                    "label": label,
                                    "relative_path": row["relative_path"],
                                    "repeat": repeat,
                                },
                                "label": label,
                                "manifest_index": manifest_index,
                                "order_slot": order_slot,
                                "record_type": "observation",
                                "relative_path": row["relative_path"],
                                "repeat": repeat,
                                "schema_version": 1,
                                "sequence": sequence,
                                "source_bytes": row["bytes"],
                                "source_path": row["path"],
                                "source_sha256": row["sha256"],
                            }
                        )
                        observations.append(observation)
                        sequence += 1
            if journal.last_hash is None:
                raise CompareError("journal did not produce a chain head")
            chain_head = journal.last_hash
        if binary.stat().st_size != plan["binary_size"] or sha256_file(binary) != binary_sha256:
            raise CompareError("solver binary changed during the comparison")
        summary = make_summary(
            plan=plan,
            journal=args.out,
            chain_head=chain_head,
            observations=observations,
        )
        atomic_write(args.summary, canonical_bytes(summary))
    except (CompareError, OSError) as error:
        print(f"rollback-control comparison error: {error}", file=sys.stderr)
        return 2
    print(
        f"{args.comparison}: wrote {len(observations)} observations for "
        f"{len(selected)} rows (shard {args.shard_index}/{args.shard_count})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
