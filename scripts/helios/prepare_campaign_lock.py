#!/usr/bin/env python3
"""Freeze the exact structural Viper configuration for a Helios campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
BENCH_DIR = SCRIPT_DIR.parent / "bench"
if str(BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(BENCH_DIR))

import freeze_campaign as freezer  # noqa: E402


CANDIDATE_CONFIGURATION = "quotient-portfolio"
CANDIDATE_ARGV = [
    "{binary}",
    "fabric-solve",
    "--engine",
    "quotient-portfolio",
    "{instance}",
]
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


class PreparationError(ValueError):
    """Raised when an input or the resulting lock is not exact."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_config(path: Path, solver_revision: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PreparationError(f"cannot read solver configuration: {error}") from error
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise PreparationError("solver configuration must use schema_version 1")
    solvers = value.get("solvers")
    if not isinstance(solvers, list):
        raise PreparationError("solver configuration lacks solvers")
    candidates = [
        record
        for record in solvers
        if isinstance(record, dict) and record.get("id") == "euf-viper"
    ]
    if len(candidates) != 1:
        raise PreparationError("solver configuration needs one euf-viper record")
    candidate = candidates[0]
    if candidate.get("comparator_id") != "euf-viper":
        raise PreparationError("euf-viper comparator_id drifted")
    if candidate.get("configuration") != CANDIDATE_CONFIGURATION:
        raise PreparationError(
            f"euf-viper configuration must be {CANDIDATE_CONFIGURATION!r}"
        )
    if candidate.get("argv_template") != CANDIDATE_ARGV:
        raise PreparationError("euf-viper argv_template is not quotient-portfolio")
    expected_version = f"0.1.0+{solver_revision}.quotient-portfolio"
    if candidate.get("version") != expected_version:
        raise PreparationError(
            f"euf-viper version must bind solver revision {solver_revision}"
        )
    return value


def exact_solver_loader(
    solver_revision: str,
) -> Callable[[Path, dict[str, Any], Path], tuple[list[dict[str, Any]], str]]:
    """Extend the v1 freezer's candidate pair without changing lock bytes later."""

    def load_solvers(
        config_path: Path, spec: dict[str, Any], repository_root: Path
    ) -> tuple[list[dict[str, Any]], str]:
        config = read_config(config_path, solver_revision)
        raw_solvers = config["solvers"]

        expected: set[tuple[str, str]] = {
            ("euf-viper", CANDIDATE_CONFIGURATION)
        }
        expected_versions: dict[str, str] = {}
        for comparator in spec["comparators"]:
            comparator_id = comparator["id"]
            expected_versions[comparator_id] = comparator["version"]
            configurations = comparator.get("configurations", ["default"])
            expected.update(
                (comparator_id, configuration)
                for configuration in configurations
            )

        seen_ids: set[str] = set()
        seen_pairs: set[tuple[str, str]] = set()
        solvers: list[dict[str, Any]] = []
        for index, raw in enumerate(raw_solvers):
            if not isinstance(raw, dict):
                raise freezer.FreezeError(
                    f"solver configuration record {index} must be an object"
                )
            identifier = raw.get("id")
            comparator_id = raw.get("comparator_id")
            configuration = raw.get("configuration")
            version = raw.get("version")
            if not isinstance(identifier, str) or not identifier:
                raise freezer.FreezeError(
                    f"solver configuration record {index} lacks id"
                )
            if identifier in seen_ids:
                raise freezer.FreezeError(f"duplicate solver id {identifier!r}")
            if not isinstance(comparator_id, str) or not comparator_id:
                raise freezer.FreezeError(
                    f"solver {identifier!r} lacks comparator_id"
                )
            if not isinstance(configuration, str) or not configuration:
                raise freezer.FreezeError(
                    f"solver {identifier!r} lacks configuration"
                )
            pair = (comparator_id, configuration)
            if pair in seen_pairs:
                raise freezer.FreezeError(
                    f"duplicate solver configuration {pair!r}"
                )
            if pair not in expected:
                raise freezer.FreezeError(
                    f"unexpected solver configuration {pair!r}"
                )
            if not isinstance(version, str) or not version:
                raise freezer.FreezeError(f"solver {identifier!r} lacks version")
            if (
                comparator_id in expected_versions
                and version != expected_versions[comparator_id]
            ):
                raise freezer.FreezeError(
                    f"solver {identifier!r} version {version!r} does not match "
                    f"campaign {expected_versions[comparator_id]!r}"
                )
            binary_value = raw.get("binary")
            if not isinstance(binary_value, str) or not binary_value:
                raise freezer.FreezeError(
                    f"solver {identifier!r} lacks binary"
                )
            binary = Path(binary_value)
            if not binary.is_absolute():
                binary = repository_root / binary
            binary = binary.resolve()
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise freezer.FreezeError(
                    f"solver binary is not executable: {binary}"
                )
            actual_hash = freezer.sha256_file(binary)
            expected_hash = raw.get("sha256")
            if (
                not isinstance(expected_hash, str)
                or not freezer.HEX64.fullmatch(expected_hash)
            ):
                raise freezer.FreezeError(
                    f"solver {identifier!r} requires a pinned sha256"
                )
            if actual_hash != expected_hash:
                raise freezer.FreezeError(
                    f"solver binary hash drift for {identifier}: "
                    f"expected {expected_hash}, got {actual_hash}"
                )
            template = freezer._validate_template(
                identifier, raw.get("argv_template")
            )
            version_output = freezer._version_output(
                binary, raw.get("version_argv")
            )
            expected_fragment = raw.get("version_output_contains")
            if expected_fragment is not None and (
                not isinstance(expected_fragment, str)
                or version_output is None
                or expected_fragment not in version_output
            ):
                raise freezer.FreezeError(
                    f"solver {identifier!r} version output lacks "
                    f"{expected_fragment!r}"
                )
            environment = raw.get("environment", {})
            if not isinstance(environment, dict) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in environment.items()
            ):
                raise freezer.FreezeError(
                    f"solver {identifier!r} environment must map strings"
                )
            solvers.append(
                {
                    "id": identifier,
                    "comparator_id": comparator_id,
                    "configuration": configuration,
                    "version": version,
                    "binary": str(binary),
                    "sha256": actual_hash,
                    "argv_template": template,
                    "version_output": version_output,
                    "version_output_sha256": (
                        freezer.sha256_bytes(version_output.encode("utf-8"))
                        if version_output is not None
                        else None
                    ),
                    "environment": dict(sorted(environment.items())),
                }
            )
            seen_ids.add(identifier)
            seen_pairs.add(pair)

        missing = sorted(expected - seen_pairs)
        if missing:
            raise freezer.FreezeError(
                f"solver configuration is missing {missing!r}"
            )
        solvers.sort(key=lambda item: item["id"])
        return solvers, freezer.sha256_file(config_path)

    return load_solvers


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    if not HEX40.fullmatch(args.solver_revision):
        raise PreparationError("solver revision must be a full lowercase Git hash")
    if not HEX40.fullmatch(args.orchestration_revision):
        raise PreparationError(
            "orchestration revision must be a full lowercase Git hash"
        )
    authoritative_path = args.solver_config.resolve(strict=True)
    taxonomy_path = args.taxonomy.resolve(strict=True)
    if args.solver_config.is_symlink() or not authoritative_path.is_file():
        raise PreparationError("solver configuration must be a regular file")
    if args.taxonomy.is_symlink() or not taxonomy_path.is_file():
        raise PreparationError("taxonomy must be a regular file")
    read_config(authoritative_path, args.solver_revision)

    loader = exact_solver_loader(args.solver_revision)
    with mock.patch.object(freezer, "load_solvers", loader):
        lock = freezer.make_lock(
            spec_path=args.spec,
            manifest_path=args.manifest,
            solver_config_path=authoritative_path,
            repository=args.repository,
            corpus_root=args.corpus_root,
            taxonomy_path=taxonomy_path,
            budgets_s=args.budget,
            cpu_ids=[0],
            memory_bytes=args.memory_bytes,
            order="balanced_latin_square",
            output_directory=args.output_directory,
            timeout_grace_s=args.timeout_grace_s,
            allow_dirty=False,
        )

    if lock["repository"]["commit"] != args.orchestration_revision:
        raise PreparationError("lock recorded the wrong orchestration revision")
    if lock["promotion_eligible"] is not True:
        raise PreparationError("lock is not promotion eligible")
    if lock["corpus"]["taxonomy_path"] != str(taxonomy_path):
        raise PreparationError("lock recorded the wrong taxonomy path")
    if lock["corpus"]["taxonomy_sha256"] != sha256_file(taxonomy_path):
        raise PreparationError("lock recorded the wrong taxonomy hash")
    if lock["solver_config"] != {
        "path": str(authoritative_path),
        "sha256": sha256_file(authoritative_path),
    }:
        raise PreparationError("lock did not bind the authoritative solver config")
    candidates = [record for record in lock["solvers"] if record["id"] == "euf-viper"]
    if len(candidates) != 1:
        raise PreparationError("lock does not contain exactly one euf-viper")
    candidate = candidates[0]
    if candidate["configuration"] != CANDIDATE_CONFIGURATION:
        raise PreparationError("lock candidate configuration drifted")
    if candidate["argv_template"] != CANDIDATE_ARGV:
        raise PreparationError("lock candidate argv drifted")
    if lock["lock_sha256"] != freezer.sha256_bytes(
        freezer.canonical_bytes({**lock, "lock_sha256": ""})
    ):
        raise PreparationError("freezer returned an invalid lock self-hash")
    return lock


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--taxonomy", type=Path, required=True)
    parser.add_argument("--solver-config", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--solver-revision", required=True)
    parser.add_argument("--orchestration-revision", required=True)
    parser.add_argument("--budget", type=int, action="append", required=True)
    parser.add_argument("--memory-bytes", type=int, required=True)
    parser.add_argument("--timeout-grace-s", type=float, default=0.25)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists() or args.out.is_symlink():
        parser.error(f"refuse to replace existing lock: {args.out}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        lock = prepare(args)
    except (PreparationError, freezer.FreezeError, OSError) as error:
        parser.exit(2, f"prepare failed: {error}\n")
    freezer.atomic_write(args.out, lock)
    candidate = next(
        record for record in lock["solvers"] if record["id"] == "euf-viper"
    )
    print(
        json.dumps(
            {
                "candidate_argv": CANDIDATE_ARGV,
                "candidate_configuration": CANDIDATE_CONFIGURATION,
                "candidate_sha256": candidate["sha256"],
                "lock_sha256": lock["lock_sha256"],
                "orchestration_revision": args.orchestration_revision,
                "promotion_eligible": lock["promotion_eligible"],
                "solver_revision": args.solver_revision,
                "taxonomy_sha256": lock["corpus"]["taxonomy_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
