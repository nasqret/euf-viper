#!/usr/bin/env python3
"""Strictly reconstruct and verify a component-quotient RAM census bundle."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import census_component_quotient_ram as census  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--lock", type=Path, default=census.DEFAULT_LOCK_PATH)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--aggregate", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--receipt-out", type=Path, required=True)
    parser.add_argument("--require-validity", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    inputs = {
        args.manifest.resolve(strict=False),
        args.lock.resolve(strict=False),
        args.records.resolve(strict=False),
        args.aggregate.resolve(strict=False),
        args.targets.resolve(strict=False),
        Path(__file__).resolve(strict=False),
        Path(census.__file__).resolve(strict=False),
    }
    receipt_path = args.receipt_out.resolve(strict=False)
    if receipt_path in inputs:
        parser.exit(2, "verification receipt must not overwrite an input\n")
    try:
        receipt = census.verify_census_bundle(
            args.manifest,
            args.records,
            args.aggregate,
            args.targets,
            repository_root=args.repository_root,
            lock_path=args.lock,
        )
        census._atomic_write(
            ((args.receipt_out, census.canonical_json_bytes(receipt)),)
        )
    except census.CensusError as error:
        parser.exit(2, f"component quotient bundle verification failed: {error}\n")
    print(
        f"verified=true sources={receipt['sources']} targets={receipt['targets']} "
        f"validity={str(receipt['validity_pass']).lower()} "
        f"records_sha256={receipt['hashes']['records_jsonl_sha256']}"
    )
    if args.require_validity and receipt["validity_pass"] is not True:
        parser.exit(2, "component quotient bundle validity gate failed\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
