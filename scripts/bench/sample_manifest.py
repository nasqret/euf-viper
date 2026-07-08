#!/usr/bin/env python3
"""Create a deterministic sampled manifest from a JSONL manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def stable_key(row: dict, seed: str) -> str:
    text = f"{seed}\0{row.get('relative_path')}\0{row.get('sha256')}"
    return hashlib.sha256(text.encode()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--limit", type=int, required=True)
    parser.add_argument("--seed", default="euf-viper-2026-07-08")
    parser.add_argument("--include-status", action="append", default=[])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    rows = [json.loads(line) for line in args.manifest.read_text().splitlines() if line.strip()]
    if args.include_status:
        allowed = set(args.include_status)
        rows = [row for row in rows if row.get("status") in allowed]
    rows.sort(key=lambda row: stable_key(row, args.seed))
    sample = rows[: args.limit]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        for row in sample:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    print(f"sample={args.out} files={len(sample)} seed={args.seed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
