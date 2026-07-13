#!/usr/bin/env python3
"""Freeze a QF_UF campaign into an immutable, hash-bound execution lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from validate_campaign_spec import CampaignSpecError, load_and_validate  # noqa: E402


HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RESULTS = {"sat", "unsat"}
PLACEHOLDERS = {"{binary}", "{instance}", "{budget_s}"}
DEFAULT_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "OMP_NUM_THREADS": "1",
    "TZ": "UTC",
}


class FreezeError(ValueError):
    """Raised when any byte or campaign invariant cannot be frozen exactly."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise FreezeError(f"cannot read {context} {path}: {error}") from error
    if not isinstance(value, dict):
        raise FreezeError(f"{context} root must be an object")
    return value


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip()
        raise FreezeError(f"git {' '.join(arguments)} failed: {message}")
    return completed.stdout.strip()


def repository_record(repository: Path, allow_dirty: bool) -> dict[str, Any]:
    root = Path(_git(repository, "rev-parse", "--show-toplevel")).resolve()
    commit = _git(root, "rev-parse", "HEAD")
    commit_time = _git(root, "show", "-s", "--format=%cI", "HEAD")
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=no")
    clean = not bool(status)
    if not clean and not allow_dirty:
        raise FreezeError("repository has tracked modifications; refuse promotion lock")
    return {
        "root": str(root),
        "commit": commit,
        "commit_time": commit_time,
        "clean": clean,
        "promotion_eligible": clean,
    }


def _load_jsonl(path: Path, context: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as error:
                    raise FreezeError(
                        f"{context} {path}:{line_number} is invalid JSON: {error}"
                    ) from error
                if not isinstance(value, dict):
                    raise FreezeError(
                        f"{context} {path}:{line_number} must be an object"
                    )
                records.append(value)
    except (OSError, UnicodeError) as error:
        raise FreezeError(f"cannot read {context} {path}: {error}") from error
    if not records:
        raise FreezeError(f"{context} {path} is empty")
    return records


def load_taxonomy(path: Path | None) -> tuple[dict[str, dict[str, Any]], str | None]:
    if path is None:
        return {}, None
    taxonomy: dict[str, dict[str, Any]] = {}
    for record in _load_jsonl(path, "taxonomy"):
        relative = record.get("relative_path")
        if not isinstance(relative, str) or not relative:
            raise FreezeError("taxonomy record lacks relative_path")
        if relative in taxonomy:
            raise FreezeError(f"duplicate taxonomy path {relative!r}")
        family = record.get("family", record.get("source_family"))
        lineage = record.get("lineage", record.get("generator_lineage"))
        normalized = record.get(
            "normalized_sha256",
            record.get(
                "normalized_fingerprint", record.get("normalized_token_sha256")
            ),
        )
        split = record.get("split")
        if not isinstance(family, str) or not family:
            raise FreezeError(f"taxonomy {relative!r} lacks family")
        if not isinstance(lineage, str) or not lineage:
            raise FreezeError(f"taxonomy {relative!r} lacks lineage")
        if not isinstance(normalized, str) or not HEX64.fullmatch(normalized):
            raise FreezeError(f"taxonomy {relative!r} has invalid normalized hash")
        if split not in {"dev", "development", "holdout"}:
            raise FreezeError(f"taxonomy {relative!r} has invalid split")
        taxonomy[relative] = {
            "family": family,
            "lineage": lineage,
            "normalized_sha256": normalized,
            "split": "dev" if split == "development" else split,
        }
    return taxonomy, sha256_file(path)


def load_instances(
    manifest: Path, corpus_root: Path | None, taxonomy_path: Path | None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = _load_jsonl(manifest, "manifest")
    taxonomy, taxonomy_sha = load_taxonomy(taxonomy_path)
    root = (corpus_root or manifest.parent).resolve()
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    instances: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        identifier = row.get("id")
        relative = row.get("relative_path")
        expected = row.get("status")
        expected_hash = row.get("sha256")
        if not isinstance(identifier, (str, int)) or isinstance(identifier, bool):
            raise FreezeError(f"manifest record {index} has invalid id")
        identifier_text = str(identifier)
        if identifier_text in seen_ids:
            raise FreezeError(f"duplicate manifest id {identifier_text!r}")
        if not isinstance(relative, str) or not relative:
            raise FreezeError(f"manifest record {index} lacks relative_path")
        if relative in seen_paths:
            raise FreezeError(f"duplicate manifest path {relative!r}")
        if expected not in RESULTS:
            raise FreezeError(f"manifest {relative!r} has invalid status {expected!r}")
        if not isinstance(expected_hash, str) or not HEX64.fullmatch(expected_hash):
            raise FreezeError(f"manifest {relative!r} has invalid sha256")

        declared_path = row.get("path")
        if isinstance(declared_path, str) and declared_path:
            instance_path = Path(declared_path).resolve()
        else:
            instance_path = (root / relative).resolve()
        try:
            instance_path.relative_to(root)
        except ValueError as error:
            raise FreezeError(
                f"manifest path escapes corpus root: {instance_path} not under {root}"
            ) from error
        if not instance_path.is_file():
            raise FreezeError(f"manifest instance is not a file: {instance_path}")
        actual_hash = sha256_file(instance_path)
        if actual_hash != expected_hash:
            raise FreezeError(
                f"manifest instance hash drift for {relative}: "
                f"expected {expected_hash}, got {actual_hash}"
            )
        byte_count = instance_path.stat().st_size
        if "bytes" in row and row["bytes"] != byte_count:
            raise FreezeError(f"manifest instance size drift for {relative}")

        record: dict[str, Any] = {
            "id": identifier_text,
            "relative_path": relative,
            "path": str(instance_path),
            "sha256": actual_hash,
            "bytes": byte_count,
            "status": expected,
        }
        if taxonomy:
            taxon = taxonomy.get(relative)
            if taxon is None:
                raise FreezeError(f"taxonomy is missing {relative!r}")
            record.update(taxon)
        instances.append(record)
        seen_ids.add(identifier_text)
        seen_paths.add(relative)

    if taxonomy and set(taxonomy) != seen_paths:
        extras = sorted(set(taxonomy) - seen_paths)
        raise FreezeError(f"taxonomy contains paths outside manifest: {extras[:3]!r}")
    instances.sort(key=lambda item: (item["relative_path"], item["id"]))
    return instances, {
        "manifest_path": str(manifest.resolve()),
        "manifest_sha256": sha256_file(manifest),
        "taxonomy_path": str(taxonomy_path.resolve()) if taxonomy_path else None,
        "taxonomy_sha256": taxonomy_sha,
        "root": str(root),
    }


def _validate_template(identifier: str, template: Any) -> list[str]:
    if not isinstance(template, list) or not template or any(
        not isinstance(item, str) or not item for item in template
    ):
        raise FreezeError(f"solver {identifier!r} argv_template must be strings")
    joined = "\0".join(template)
    unknown = re.findall(r"\{[^{}]+\}", joined)
    if set(unknown) - PLACEHOLDERS:
        raise FreezeError(
            f"solver {identifier!r} has unknown placeholders "
            f"{sorted(set(unknown) - PLACEHOLDERS)!r}"
        )
    if joined.count("{binary}") != 1 or joined.count("{instance}") != 1:
        raise FreezeError(
            f"solver {identifier!r} template needs one binary and one instance"
        )
    return list(template)


def _version_output(binary: Path, argv: Any) -> str | None:
    if argv is None:
        return None
    if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
        raise FreezeError("version_argv must be an array of strings")
    completed = subprocess.run(
        [str(binary), *argv],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=DEFAULT_ENVIRONMENT,
    )
    output = (completed.stdout + completed.stderr).strip()
    if completed.returncode != 0 or not output:
        raise FreezeError(
            f"version command for {binary} failed with {completed.returncode}: {output}"
        )
    return output[:4096]


def load_solvers(
    config_path: Path, spec: dict[str, Any], repository_root: Path
) -> tuple[list[dict[str, Any]], str]:
    config = read_json(config_path, "solver configuration")
    if config.get("schema_version") != 1:
        raise FreezeError("solver configuration schema_version must be 1")
    raw_solvers = config.get("solvers")
    if not isinstance(raw_solvers, list) or not raw_solvers:
        raise FreezeError("solver configuration solvers must be a non-empty array")

    expected: set[tuple[str, str]] = {("euf-viper", "default")}
    expected_versions: dict[str, str] = {}
    for comparator in spec["comparators"]:
        comparator_id = comparator["id"]
        expected_versions[comparator_id] = comparator["version"]
        configurations = comparator.get("configurations", ["default"])
        expected.update((comparator_id, configuration) for configuration in configurations)

    seen_ids: set[str] = set()
    seen_pairs: set[tuple[str, str]] = set()
    solvers: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_solvers):
        if not isinstance(raw, dict):
            raise FreezeError(f"solver configuration record {index} must be an object")
        identifier = raw.get("id")
        comparator_id = raw.get("comparator_id")
        configuration = raw.get("configuration", "default")
        version = raw.get("version")
        if not isinstance(identifier, str) or not identifier:
            raise FreezeError(f"solver configuration record {index} lacks id")
        if identifier in seen_ids:
            raise FreezeError(f"duplicate solver id {identifier!r}")
        if not isinstance(comparator_id, str) or not comparator_id:
            raise FreezeError(f"solver {identifier!r} lacks comparator_id")
        if not isinstance(configuration, str) or not configuration:
            raise FreezeError(f"solver {identifier!r} lacks configuration")
        pair = (comparator_id, configuration)
        if pair in seen_pairs:
            raise FreezeError(f"duplicate solver configuration {pair!r}")
        if pair not in expected:
            raise FreezeError(f"unexpected solver configuration {pair!r}")
        if not isinstance(version, str) or not version:
            raise FreezeError(f"solver {identifier!r} lacks version")
        if comparator_id in expected_versions and version != expected_versions[comparator_id]:
            raise FreezeError(
                f"solver {identifier!r} version {version!r} does not match "
                f"campaign {expected_versions[comparator_id]!r}"
            )
        binary_value = raw.get("binary")
        if not isinstance(binary_value, str) or not binary_value:
            raise FreezeError(f"solver {identifier!r} lacks binary")
        binary = Path(binary_value)
        if not binary.is_absolute():
            binary = repository_root / binary
        binary = binary.resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise FreezeError(f"solver binary is not executable: {binary}")
        actual_hash = sha256_file(binary)
        expected_hash = raw.get("sha256")
        if not isinstance(expected_hash, str) or not HEX64.fullmatch(expected_hash):
            raise FreezeError(f"solver {identifier!r} requires a pinned sha256")
        if actual_hash != expected_hash:
            raise FreezeError(
                f"solver binary hash drift for {identifier}: "
                f"expected {expected_hash}, got {actual_hash}"
            )
        template = _validate_template(identifier, raw.get("argv_template"))
        version_output = _version_output(binary, raw.get("version_argv"))
        expected_fragment = raw.get("version_output_contains")
        if expected_fragment is not None and (
            not isinstance(expected_fragment, str)
            or version_output is None
            or expected_fragment not in version_output
        ):
            raise FreezeError(
                f"solver {identifier!r} version output lacks {expected_fragment!r}"
            )
        environment = raw.get("environment", {})
        if not isinstance(environment, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in environment.items()
        ):
            raise FreezeError(f"solver {identifier!r} environment must map strings")
        evidence = raw.get("evidence")
        if evidence is not None:
            if not isinstance(evidence, dict) or set(evidence) != {
                "schema",
                "argv_flag",
                "accepted_decisive_statuses",
            }:
                raise FreezeError(f"solver {identifier!r} has invalid evidence contract")
            if evidence["schema"] != "euf-viper.production-evidence.v1":
                raise FreezeError(f"solver {identifier!r} has unsupported evidence schema")
            if evidence["argv_flag"] != "--evidence-out":
                raise FreezeError(f"solver {identifier!r} has invalid evidence argv flag")
            if evidence["accepted_decisive_statuses"] != ["sat"]:
                raise FreezeError(
                    f"solver {identifier!r} must fail closed on production UNSAT evidence"
                )
        solver_record = {
            "id": identifier,
            "comparator_id": comparator_id,
            "configuration": configuration,
            "version": version,
            "binary": str(binary),
            "sha256": actual_hash,
            "argv_template": template,
            "version_output": version_output,
            "version_output_sha256": (
                sha256_bytes(version_output.encode("utf-8"))
                if version_output is not None
                else None
            ),
            "environment": dict(sorted(environment.items())),
        }
        if evidence is not None:
            solver_record["evidence"] = evidence
        solvers.append(solver_record)
        seen_ids.add(identifier)
        seen_pairs.add(pair)

    missing = sorted(expected - seen_pairs)
    if missing:
        raise FreezeError(f"solver configuration is missing {missing!r}")
    solvers.sort(key=lambda item: item["id"])
    return solvers, sha256_file(config_path)


def make_lock(
    *,
    spec_path: Path,
    manifest_path: Path,
    solver_config_path: Path,
    repository: Path,
    corpus_root: Path | None,
    taxonomy_path: Path | None,
    budgets_s: list[int] | None,
    cpu_ids: list[int],
    memory_bytes: int,
    order: str,
    output_directory: Path,
    timeout_grace_s: float,
    allow_dirty: bool,
) -> dict[str, Any]:
    try:
        validated = load_and_validate(spec_path)
    except CampaignSpecError as error:
        raise FreezeError("invalid campaign specification: " + "; ".join(error.errors))
    spec = read_json(spec_path, "campaign specification")
    repository_data = repository_record(repository, allow_dirty)
    root = Path(repository_data["root"])
    release_lock_record = spec.get("release_lock")
    if not isinstance(release_lock_record, dict):
        raise FreezeError("campaign specification lacks release_lock")
    release_lock_path = Path(str(release_lock_record.get("path", "")))
    if not release_lock_path.is_absolute():
        release_lock_path = root / release_lock_path
    release_lock_path = release_lock_path.resolve()
    expected_release_hash = release_lock_record.get("sha256")
    if not release_lock_path.is_file():
        raise FreezeError(f"solver release lock is not a file: {release_lock_path}")
    actual_release_hash = sha256_file(release_lock_path)
    if actual_release_hash != expected_release_hash:
        raise FreezeError(
            "solver release lock hash drift: "
            f"expected {expected_release_hash}, got {actual_release_hash}"
        )
    instances, corpus_metadata = load_instances(
        manifest_path, corpus_root, taxonomy_path
    )
    solvers, solver_config_sha = load_solvers(solver_config_path, spec, root)
    declared_budgets = list(spec["budgets_s"])
    selected_budgets = declared_budgets if budgets_s is None else list(budgets_s)
    if (
        not selected_budgets
        or len(set(selected_budgets)) != len(selected_budgets)
        or selected_budgets != sorted(selected_budgets)
        or any(budget not in declared_budgets for budget in selected_budgets)
    ):
        raise FreezeError(
            f"selected budgets must be a sorted non-empty subset of {declared_budgets!r}"
        )
    if not cpu_ids or any(cpu_id < 0 for cpu_id in cpu_ids):
        raise FreezeError("at least one non-negative CPU id is required")
    if len(cpu_ids) != len(set(cpu_ids)):
        raise FreezeError("CPU ids must be unique")
    if memory_bytes <= 0:
        raise FreezeError("memory_bytes must be positive")
    if order not in {"abba", "balanced_latin_square"}:
        raise FreezeError("order must be abba or balanced_latin_square")
    if order == "abba" and len(solvers) != 2:
        raise FreezeError("abba order requires exactly two solver configurations")
    if timeout_grace_s < 0:
        raise FreezeError("timeout_grace_s cannot be negative")

    promotion_eligible = bool(repository_data["promotion_eligible"] and taxonomy_path)
    lock: dict[str, Any] = {
        "schema_version": 1,
        "campaign_id": validated["campaign_id"],
        "lock_sha256": "",
        "created_from_commit_time": repository_data["commit_time"],
        "promotion_eligible": promotion_eligible,
        "spec": {
            "path": str(spec_path.resolve()),
            "sha256": sha256_file(spec_path),
        },
        "repository": repository_data,
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "corpus": {
            "id": spec["baseline"]["reference_corpus"],
            **corpus_metadata,
            "instances": instances,
        },
        "solver_config": {
            "path": str(solver_config_path.resolve()),
            "sha256": solver_config_sha,
        },
        "solver_release_lock": {
            "path": str(release_lock_path),
            "sha256": actual_release_hash,
        },
        "solvers": solvers,
        "budgets_s": selected_budgets,
        "execution": {
            "resource_model": spec["scope"]["primary_resource_model"],
            "cpu_ids": cpu_ids,
            "memory_bytes": memory_bytes,
            "order": order,
            "environment": DEFAULT_ENVIRONMENT,
            "timeout_grace_s": timeout_grace_s,
        },
        "output": {
            "directory": str(output_directory.resolve()),
            "journal": "journal.jsonl",
            "raw": "raw.jsonl",
            "summary": "summary.json",
        },
    }
    lock["lock_sha256"] = sha256_bytes(canonical_bytes({**lock, "lock_sha256": ""}))
    return lock


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(canonical_bytes(payload))
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--solver-config", type=Path, required=True)
    parser.add_argument("--taxonomy", type=Path)
    parser.add_argument("--budget", type=int, action="append")
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--corpus-root", type=Path)
    parser.add_argument("--cpu-id", type=int, action="append", required=True)
    parser.add_argument("--memory-bytes", type=int, default=8 * 1024**3)
    parser.add_argument(
        "--order",
        choices=("abba", "balanced_latin_square"),
        default="balanced_latin_square",
    )
    parser.add_argument("--timeout-grace-s", type=float, default=0.25)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    try:
        payload = make_lock(
            spec_path=args.spec,
            manifest_path=args.manifest,
            solver_config_path=args.solver_config,
            repository=args.repository,
            corpus_root=args.corpus_root,
            taxonomy_path=args.taxonomy,
            budgets_s=args.budget,
            cpu_ids=args.cpu_id,
            memory_bytes=args.memory_bytes,
            order=args.order,
            output_directory=args.output_directory,
            timeout_grace_s=args.timeout_grace_s,
            allow_dirty=args.allow_dirty,
        )
    except FreezeError as error:
        parser.exit(2, f"freeze failed: {error}\n")
    atomic_write(args.out, payload)
    print(json.dumps({
        "campaign_id": payload["campaign_id"],
        "instances": len(payload["corpus"]["instances"]),
        "solvers": [item["id"] for item in payload["solvers"]],
        "lock_sha256": payload["lock_sha256"],
        "promotion_eligible": payload["promotion_eligible"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
