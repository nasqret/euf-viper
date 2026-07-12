#!/usr/bin/env python3
"""Bind a prepared campaign lock to the first CPU allowed by its SLURM task."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any


class BindingError(ValueError):
    """Raised when a runtime CPU binding cannot be made immutable."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def lock_hash(lock: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes({**lock, "lock_sha256": ""})).hexdigest()


def read_lock(path: Path) -> dict[str, Any]:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BindingError(f"cannot read prepared lock {path}: {error}") from error
    if not isinstance(lock, dict) or lock.get("schema_version") != 1:
        raise BindingError("prepared lock must use schema_version 1")
    declared = lock.get("lock_sha256")
    if not isinstance(declared, str) or declared != lock_hash(lock):
        raise BindingError("prepared lock self-hash mismatch")
    if "runtime_binding" in lock:
        raise BindingError("lock already has a runtime binding")
    execution = lock.get("execution")
    if not isinstance(execution, dict) or execution.get("cpu_ids") != [0]:
        raise BindingError("prepared lock must use the single placeholder CPU id 0")
    return lock


def bind_lock(prepared: dict[str, Any], cpu_id: int) -> dict[str, Any]:
    if not isinstance(cpu_id, int) or isinstance(cpu_id, bool) or cpu_id < 0:
        raise BindingError("runtime CPU id must be a non-negative integer")
    parent_hash = prepared["lock_sha256"]
    bound = {
        **prepared,
        "lock_sha256": "",
        "execution": {**prepared["execution"], "cpu_ids": [cpu_id]},
        "runtime_binding": {
            "parent_lock_sha256": parent_hash,
            "mechanism": "first_allowed_slurm_cpu",
            "cpu_ids": [cpu_id],
        },
    }
    bound["lock_sha256"] = lock_hash(bound)
    return bound


def first_allowed_cpu() -> int:
    if not hasattr(os, "sched_getaffinity"):
        raise BindingError("sched_getaffinity is required for WMI runtime binding")
    allowed = sorted(os.sched_getaffinity(0))
    if not allowed:
        raise BindingError("the current process has no allowed CPUs")
    return allowed[0]


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(canonical_bytes(payload))
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prepared", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        prepared = read_lock(args.prepared)
        cpu_id = first_allowed_cpu()
        bound = bind_lock(prepared, cpu_id)
    except BindingError as error:
        parser.exit(2, f"bind failed: {error}\n")
    atomic_write(args.out, bound)
    print(
        json.dumps(
            {
                "cpu_id": cpu_id,
                "parent_lock_sha256": prepared["lock_sha256"],
                "lock_sha256": bound["lock_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
