#!/usr/bin/env python3
"""Derive immutable, disjoint WMI shard locks from one validated campaign lock."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


class ShardError(ValueError):
    """Raised when a parent lock or requested partition is invalid."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def lock_hash(lock: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes({**lock, "lock_sha256": ""})).hexdigest()


def load_lock(path: Path) -> dict[str, Any]:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ShardError(f"cannot read parent lock {path}: {error}") from error
    if not isinstance(lock, dict) or lock.get("schema_version") != 1:
        raise ShardError("parent lock must use schema_version 1")
    expected = lock.get("lock_sha256")
    if not isinstance(expected, str) or expected != lock_hash(lock):
        raise ShardError("parent lock self-hash mismatch")
    if "shard" in lock:
        raise ShardError("refuse to shard an already sharded lock")
    corpus = lock.get("corpus")
    instances = corpus.get("instances") if isinstance(corpus, dict) else None
    if not isinstance(instances, list) or not instances:
        raise ShardError("parent lock has no corpus instances")
    output = lock.get("output")
    if not isinstance(output, dict) or not isinstance(output.get("directory"), str):
        raise ShardError("parent lock has no output directory")
    return lock


def derive_shards(parent: dict[str, Any], count: int) -> list[dict[str, Any]]:
    instances = parent["corpus"]["instances"]
    if count < 1:
        raise ShardError("shard count must be positive")
    if count > len(instances):
        raise ShardError("shard count cannot exceed instance count")
    parent_hash = parent["lock_sha256"]
    base_output = Path(parent["output"]["directory"])
    shards: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index in range(count):
        selected = [
            instance
            for position, instance in enumerate(instances)
            if position % count == index
        ]
        if not selected:
            raise ShardError(f"shard {index} would be empty")
        for instance in selected:
            key = (str(instance.get("id")), str(instance.get("relative_path")))
            if key in seen:
                raise ShardError(f"instance appears in multiple shards: {key!r}")
            seen.add(key)
        shard = {
            **parent,
            "lock_sha256": "",
            "promotion_eligible": parent.get("promotion_eligible") is True,
            "corpus": {**parent["corpus"], "instances": selected},
            "output": {
                **parent["output"],
                "directory": str(base_output / f"shard-{index:04d}"),
            },
            "shard": {
                "index": index,
                "count": count,
                "parent_lock_sha256": parent_hash,
            },
        }
        shard["lock_sha256"] = lock_hash(shard)
        shards.append(shard)
    expected_keys = {
        (str(instance.get("id")), str(instance.get("relative_path")))
        for instance in instances
    }
    if seen != expected_keys:
        raise ShardError("shards do not form an exact partition")
    return shards


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(canonical_bytes(payload))
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("parent", type=Path)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        parent = load_lock(args.parent)
        shards = derive_shards(parent, args.count)
    except ShardError as error:
        parser.exit(2, f"shard failed: {error}\n")
    for shard in shards:
        index = shard["shard"]["index"]
        atomic_write(args.out_dir / f"lock-{index:04d}.json", shard)
    print(
        json.dumps(
            {
                "parent_lock_sha256": parent["lock_sha256"],
                "shards": len(shards),
                "instances": sum(
                    len(shard["corpus"]["instances"]) for shard in shards
                ),
                "lock_sha256": [shard["lock_sha256"] for shard in shards],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
