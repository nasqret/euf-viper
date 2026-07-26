#!/usr/bin/env python3
"""Run one command and atomically record Linux child resource usage."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import resource
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "euf-viper.helios-resource-usage.v1"


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def atomic_write_new(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refuse to replace resource record: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o444)
        os.link(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def delta(after: resource.struct_rusage, before: resource.struct_rusage, name: str) -> int | float:
    return getattr(after, name) - getattr(before, name)


def run(command: list[str], output: Path) -> int:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started_at = utc_now()
    started = time.monotonic_ns()
    completed = subprocess.run(command, check=False)
    elapsed_ns = time.monotonic_ns() - started
    finished_at = utc_now()
    after = resource.getrusage(resource.RUSAGE_CHILDREN)

    return_code = completed.returncode
    normalized_return_code = return_code if return_code >= 0 else 128 - return_code
    payload = {
        "argv": command,
        "finished_at": finished_at,
        "involuntary_context_switches": delta(after, before, "ru_nivcsw"),
        "major_page_faults": delta(after, before, "ru_majflt"),
        "max_rss_kib": after.ru_maxrss // 1024 if sys.platform == "darwin" else after.ru_maxrss,
        "minor_page_faults": delta(after, before, "ru_minflt"),
        "return_code": normalized_return_code,
        "schema_version": SCHEMA_VERSION,
        "started_at": started_at,
        "system_time_s": delta(after, before, "ru_stime"),
        "user_time_s": delta(after, before, "ru_utime"),
        "voluntary_context_switches": delta(after, before, "ru_nvcsw"),
        "wall_time_s": elapsed_ns / 1_000_000_000,
    }
    atomic_write_new(output, payload)
    return min(normalized_return_code, 255)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("a command is required after --")
    try:
        return run(command, args.out)
    except (FileExistsError, OSError) as error:
        parser.exit(2, f"resource measurement failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
