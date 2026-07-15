#!/usr/bin/env python3
"""Validate the frozen T8 assertion-lineage census contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


EXPECTED: dict[str, Any] = {
    "campaign_id": "t8-assertion-lineage-census-v1",
    "execution": {
        "allowed_binary_subcommand": "lineage",
        "heavy_compute_site": "WMI",
        "local_full_corpus_allowed": False,
        "sat_or_unsat_result_fields_allowed": False,
        "shard_count": 64,
        "slurm_submission_status": "not_submitted",
        "solver_invocation_allowed": False,
    },
    "gates": {
        "expected_verified_records": 7503,
        "hash_errors_allowed": 0,
        "lineage_errors_allowed": 0,
        "missing_records_allowed": 0,
        "parse_errors_allowed": 0,
        "solver_invocations_allowed": 0,
        "unsupported_accounting_errors_allowed": 0,
        "verifier_errors_allowed": 0,
    },
    "identity": {
        "build_git_dirty_allowed": False,
        "build_git_revision_must_equal_campaign_revision": True,
        "build_source_revision_unique_count": 1,
        "canonical_json_required": True,
        "duplicate_json_keys_allowed": False,
        "non_finite_json_values_allowed": False,
        "parser_source_revision_unique_count": 1,
        "python_path_unique_count": 1,
        "python_sha256_unique_count": 1,
        "python_version_unique_count": 1,
        "source_binding": "no-follow-single-open-buffer.v1",
        "stale_source_allowed": False,
    },
    "parser_environment": {
        "EUF_VIPER_LEGACY_PREPROCESS_TERM_LIMIT": "1024",
        "EUF_VIPER_PROFILE": None,
        "EUF_VIPER_SCOPED_LET": "auto",
    },
    "population": {
        "expected_physical_sources": 7503,
        "expected_records": 7503,
        "expected_unique_device_inode_pairs": 7503,
        "expected_unique_relative_paths": 7503,
        "full_manifest_path": "benchmarks/smtlib-2025/qf_uf_manifest.jsonl",
        "full_manifest_sha256": (
            "9c509b0ffd35a371738dbb31865f975b43350fca5f54393f7bb5014d450a08db"
        ),
        "logic": "QF_UF",
        "release_metadata_path": "benchmarks/qf_uf_2025_metadata.json",
        "release_metadata_sha256": (
            "a5c467bd2936e80b0697320bc5896cc8400d968654ff7aa37dab6c2362e32dd7"
        ),
    },
    "schema_version": 1,
    "scope": {
        "frontier_search_allowed": False,
        "performance_claims_allowed": False,
        "simd_allowed": False,
        "source_only": True,
        "typed_ir_boundary": "Problem/BoolProblem",
    },
    "status": "preregistered_not_submitted",
    "unsupported_policy": {
        "accounted_parser_diagnostics_allowed": True,
        "diagnostic_message_and_command_identity_required": True,
        "unsupported_accounting_mismatches_allowed": 0,
    },
}


class ContractError(ValueError):
    """Raised when the frozen contract changes or becomes unsafe."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r}")


def load_contract(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="ascii"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ContractError(f"cannot load strict contract: {error}") from error
    if type(value) is not dict:
        raise ContractError("contract root must be an object")
    return value


def validate_contract(value: dict[str, Any]) -> None:
    if value != EXPECTED:
        errors: list[str] = []

        def compare(expected: Any, actual: Any, path: str) -> None:
            if type(expected) is not type(actual):
                errors.append(f"{path}: type mismatch")
            elif isinstance(expected, dict):
                if set(expected) != set(actual):
                    errors.append(f"{path}: key mismatch")
                for key in sorted(set(expected) & set(actual)):
                    compare(expected[key], actual[key], f"{path}.{key}")
            elif expected != actual:
                errors.append(f"{path}: expected {expected!r}, got {actual!r}")

        compare(EXPECTED, value, "contract")
        raise ContractError("\n".join(errors or ["contract mismatch"]))

    if value["execution"]["solver_invocation_allowed"]:
        raise ContractError("execution.solver_invocation_allowed must be false")
    if value["execution"]["slurm_submission_status"] != "not_submitted":
        raise ContractError("execution.slurm_submission_status must remain not_submitted")
    if not value["scope"]["source_only"]:
        raise ContractError("scope.source_only must be true")
    for name, allowed in value["gates"].items():
        if name.endswith("_allowed") and allowed != 0:
            raise ContractError(f"gates.{name} must be zero")


def validate_release_metadata(root: Path, contract: dict[str, Any]) -> None:
    import hashlib

    population = contract["population"]
    path = root / population["release_metadata_path"]
    try:
        content = path.read_bytes()
        metadata = json.loads(
            content.decode("ascii"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ContractError(f"cannot validate release metadata: {error}") from error
    digest = hashlib.sha256(content).hexdigest()
    if digest != population["release_metadata_sha256"]:
        raise ContractError("release metadata SHA-256 mismatch")
    if metadata.get("total_files") != population["expected_physical_sources"]:
        raise ContractError("release metadata source count mismatch")
    if metadata.get("logic") != population["logic"]:
        raise ContractError("release metadata logic mismatch")


def load_and_validate(path: Path, root: Path) -> dict[str, Any]:
    contract = load_contract(path)
    validate_contract(contract)
    validate_release_metadata(root, contract)
    return {
        "campaign_id": contract["campaign_id"],
        "expected_physical_sources": contract["population"]["expected_physical_sources"],
        "source_only": True,
        "status": contract["status"],
        "submitted": False,
        "valid": True,
    }


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = load_and_validate(args.contract, args.root.resolve(strict=True))
    except ContractError as error:
        print(f"T8 lineage contract validation failed: {error}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
