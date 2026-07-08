#!/usr/bin/env python3
"""Select one deterministic modulo shard from a JSONL benchmark manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--index", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    if args.shards < 1:
        parser.error("--shards must be at least 1")
    if not 0 <= args.index < args.shards:
        parser.error("--index must be in [0, shards)")

    rows = [
        json.loads(line)
        for line in args.manifest.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    selected = [row for offset, row in enumerate(rows) if offset % args.shards == args.index]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in selected),
        encoding="utf-8",
    )
    print(
        f"manifest={args.manifest} shards={args.shards} "
        f"index={args.index} selected={len(selected)} out={args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
