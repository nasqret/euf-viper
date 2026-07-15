#!/usr/bin/env python3
"""Run the independent, decisive verifier for a captured T5 census stage."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import component_quotient_contract as contract  # noqa: E402
from scripts.bench import independent_component_quotient_verifier as verifier  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--aggregate", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--receipt-out", type=Path, required=True)
    parser.add_argument("--require-validity", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    inputs = {
        Path(path).absolute()
        for path in (
            args.manifest,
            args.lock,
            args.records,
            args.aggregate,
            args.targets,
            Path(__file__),
            Path(verifier.__file__),
        )
    }
    receipt_path = args.receipt_out.absolute()
    if receipt_path in inputs:
        parser.exit(2, "verification receipt must not overwrite an input\n")
    try:
        snapshot = verifier.capture_snapshot(
            repository_root=args.repository_root,
            lock_path=args.lock,
            manifest_path=args.manifest,
            records_path=args.records,
            aggregate_path=args.aggregate,
            targets_path=args.targets,
            expected_manifest_sha256=args.expected_manifest_sha256,
        )
        receipt = verifier.verify_or_nondecisive(snapshot)
        verifier._write_unique_receipt(
            args.receipt_out, contract.canonical_json_bytes(receipt)
        )
    except (verifier.IndependentVerificationError, contract.ContractError) as error:
        parser.exit(2, f"component quotient independent verification failed: {error}\n")
    if args.require_validity and (
        receipt.get("decisive") is not True
        or receipt.get("validity_pass") is not True
    ):
        parser.exit(2, "component quotient independent decision is nondecisive\n")
    print(
        f"verified=true decisive={str(receipt['decisive']).lower()} "
        f"sources={receipt.get('sources', 0)} targets={receipt.get('targets', 0)} "
        f"decision={receipt['decision']} "
        f"receipt_sha256={receipt['receipt_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
