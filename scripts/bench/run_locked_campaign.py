#!/usr/bin/env python3
"""Run a frozen single-core, cold-process benchmark campaign.

Schema version 1 is the exact schema emitted by ``freeze_campaign.py``.  In
particular, the lock digest is SHA-256 over canonical JSON with
``lock_sha256`` set to the empty string.  Canonical JSON uses sorted keys,
compact separators, ASCII escaping, and one trailing newline.

The runner never inherits the ambient environment into solver children.  The
effective child environment is ``execution.environment`` updated by the
solver-specific ``environment`` object.  Solver routing and order depend only
on the ordinal positions of instances and solvers in the lock.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import platform
import re
import shutil
import signal
import stat
import string
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    import resource
except ImportError:  # pragma: no cover - the runner rejects such platforms.
    resource = None  # type: ignore[assignment]


HEX40_OR_64 = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RESULT_TOKENS = {"sat", "unsat", "unknown"}
PLACEHOLDERS = {"binary", "instance", "budget_s"}

TOP_LEVEL_KEYS = {
    "schema_version",
    "campaign_id",
    "lock_sha256",
    "created_from_commit_time",
    "promotion_eligible",
    "spec",
    "repository",
    "host",
    "corpus",
    "solver_config",
    "solver_release_lock",
    "solvers",
    "budgets_s",
    "execution",
    "output",
}
SHARD_KEYS = {"index", "count", "parent_lock_sha256"}
RUNTIME_BINDING_KEYS = {
    "parent_lock_sha256",
    "mechanism",
    "cpu_ids",
}
CONTINUATION_KEYS = {
    "mode",
    "root_lock_sha256",
    "parent_lock_path",
    "parent_lock_file_sha256",
    "parent_lock_sha256",
    "shard_bundle_sha256",
    "source_evidence_sha256",
    "shard_lock_directory",
    "shard_results_root",
    "source_budget_s",
    "target_budget_s",
    "selection_sha256",
    "selected_instances",
    "selected_runs",
    "runner_path",
    "runner_sha256",
}
RUN_SELECTION_KEYS = {"instance_id", "solver_id"}
SPEC_KEYS = {"path", "sha256"}
REPOSITORY_KEYS = {
    "root",
    "commit",
    "commit_time",
    "clean",
    "promotion_eligible",
}
HOST_KEYS = {"system", "release", "machine", "python"}
CORPUS_KEYS = {
    "id",
    "manifest_path",
    "manifest_sha256",
    "taxonomy_path",
    "taxonomy_sha256",
    "root",
    "instances",
}
INSTANCE_KEYS = {"id", "relative_path", "path", "sha256", "bytes", "status"}
TAXONOMY_INSTANCE_KEYS = {
    "family",
    "lineage",
    "normalized_sha256",
    "split",
}
SOLVER_CONFIG_KEYS = {"path", "sha256"}
SOLVER_RELEASE_LOCK_KEYS = {"path", "sha256"}
SOLVER_KEYS = {
    "id",
    "comparator_id",
    "configuration",
    "version",
    "binary",
    "sha256",
    "argv_template",
    "version_output",
    "version_output_sha256",
    "environment",
}
EVIDENCE_CONTRACT_KEYS = {
    "schema",
    "argv_flag",
    "accepted_decisive_statuses",
}
EXECUTION_KEYS = {
    "resource_model",
    "cpu_ids",
    "memory_bytes",
    "order",
    "environment",
    "timeout_grace_s",
}
OUTPUT_KEYS = {"directory", "journal", "raw", "summary"}

INVOCATION_RECORD_KEYS = {
    "record_type",
    "schema_version",
    "lock_sha256",
    "invocation",
    "started_at",
    "pid",
    "host",
    "enforcement",
    "previous_record_sha256",
    "record_sha256",
}
RUN_RECORD_KEYS = {
    "record_type",
    "schema_version",
    "lock_sha256",
    "invocation",
    "sequence",
    "key",
    "instance_id",
    "relative_path",
    "instance_sha256",
    "expected_status",
    "family",
    "solver_id",
    "solver_sha256",
    "solver_version",
    "budget_s",
    "repetition",
    "cpu_id",
    "argv",
    "environment_sha256",
    "pid",
    "started_at",
    "finished_at",
    "wall_time_s",
    "child_user_time_s",
    "child_system_time_s",
    "child_cpu_time_s",
    "max_rss_bytes",
    "exit_code",
    "termination_cause",
    "termination_signal",
    "timed_out",
    "spawn_error",
    "stdout_sha256",
    "stdout_bytes",
    "stderr_sha256",
    "stderr_bytes",
    "result_token",
    "result_token_status",
    "previous_record_sha256",
    "record_sha256",
}
PRODUCTION_EVIDENCE_KEYS = {
    "path",
    "sha256",
    "bytes",
    "schema",
    "source_sha256",
    "solver_revision",
    "solver_configuration",
    "solver_config_sha256",
    "solver_runtime_config_sha256",
    "status",
    "backend_status",
}


class CampaignError(RuntimeError):
    """Raised when execution cannot proceed without weakening the lock."""


@dataclass(frozen=True)
class ArtifactSnapshot:
    path: Path
    fingerprint: tuple[int, int, int, int, int, int]


@dataclass(frozen=True)
class Job:
    sequence: int
    instance_index: int
    instance: dict[str, Any]
    solver_index: int
    solver: dict[str, Any]
    budget_s: int | float
    repetition: int
    cpu_id: int
    argv: list[str]
    environment: dict[str, str]
    environment_sha256: str
    evidence_path: Path | None

    @property
    def key(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance["id"],
            "solver_id": self.solver["id"],
            "budget_s": self.budget_s,
            "repetition": self.repetition,
        }

    @property
    def key_bytes(self) -> bytes:
        return canonical_bytes(self.key)


@dataclass(frozen=True)
class LockedCampaign:
    lock_path: Path
    payload: dict[str, Any]
    repository_root: Path
    spec_path: Path
    manifest_path: Path
    taxonomy_path: Path | None
    solver_config_path: Path
    solver_release_lock_path: Path
    corpus_root: Path
    output_directory: Path
    journal_path: Path
    raw_path: Path
    summary_path: Path
    instance_paths: tuple[Path, ...]
    solver_paths: tuple[Path, ...]
    jobs: tuple[Job, ...]


def canonical_bytes(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise CampaignError(f"value is not canonical JSON: {error}") from error
    return (rendered + "\n").encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise CampaignError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _reject_constant(value: str) -> Any:
    raise CampaignError(f"non-finite JSON number is forbidden: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CampaignError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def parse_json_strict(text: str, context: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except CampaignError:
        raise
    except json.JSONDecodeError as error:
        raise CampaignError(f"invalid JSON in {context}: {error}") from error


def read_json_strict(path: Path, context: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise CampaignError(f"cannot read {context} {path}: {error}") from error
    value = parse_json_strict(text, f"{context} {path}")
    if type(value) is not dict:
        raise CampaignError(f"{context} root must be an object")
    return value


def require_exact_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise CampaignError(f"{context} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing or unknown:
        parts = []
        if missing:
            parts.append(f"missing keys {missing!r}")
        if unknown:
            parts.append(f"unknown keys {unknown!r}")
        raise CampaignError(f"{context} has " + " and ".join(parts))
    return value


def require_string(value: Any, context: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise CampaignError(f"{context} must be {qualifier}")
    if "\x00" in value:
        raise CampaignError(f"{context} cannot contain NUL")
    return value


def require_bool(value: Any, context: str) -> bool:
    if type(value) is not bool:
        raise CampaignError(f"{context} must be a boolean")
    return value


def require_int(value: Any, context: str, *, minimum: int | None = None) -> int:
    if type(value) is not int:
        raise CampaignError(f"{context} must be an integer")
    if minimum is not None and value < minimum:
        raise CampaignError(f"{context} must be at least {minimum}")
    return value


def require_number(
    value: Any, context: str, *, minimum: float | None = None
) -> int | float:
    if type(value) not in {int, float} or not math.isfinite(value):
        raise CampaignError(f"{context} must be a finite number")
    if minimum is not None and value < minimum:
        raise CampaignError(f"{context} must be at least {minimum}")
    return value


def require_hash(value: Any, context: str) -> str:
    digest = require_string(value, context)
    if not HEX64.fullmatch(digest):
        raise CampaignError(f"{context} must be a lowercase SHA-256 digest")
    return digest


def require_absolute_path(value: Any, context: str) -> Path:
    path = Path(require_string(value, context))
    if not path.is_absolute():
        raise CampaignError(f"{context} must be an absolute path")
    return Path(os.path.abspath(path))


def _path_under(path: Path, root: Path, context: str) -> None:
    try:
        path.relative_to(root)
    except ValueError as error:
        raise CampaignError(f"{context} escapes {root}: {path}") from error


def _output_path(directory: Path, value: Any, context: str) -> Path:
    configured = Path(require_string(value, context))
    path = configured if configured.is_absolute() else directory / configured
    path = Path(os.path.abspath(path))
    _path_under(path, directory, context)
    if path == directory:
        raise CampaignError(f"{context} must name a file below output.directory")
    return path


def _validate_environment(value: Any, context: str) -> dict[str, str]:
    if type(value) is not dict:
        raise CampaignError(f"{context} must be an object mapping strings to strings")
    result: dict[str, str] = {}
    for key, setting in value.items():
        require_string(key, f"{context} key")
        require_string(setting, f"{context}[{key!r}]", allow_empty=True)
        if "=" in key:
            raise CampaignError(f"{context} key {key!r} cannot contain '='")
        result[key] = setting
    return result


def _validate_evidence_contract(value: Any, context: str) -> dict[str, Any]:
    contract = require_exact_keys(value, EVIDENCE_CONTRACT_KEYS, context)
    if contract["schema"] != "euf-viper.production-evidence.v1":
        raise CampaignError(f"{context}.schema is unsupported")
    if contract["argv_flag"] != "--evidence-out":
        raise CampaignError(f"{context}.argv_flag must be --evidence-out")
    if contract["accepted_decisive_statuses"] != ["sat"]:
        raise CampaignError(
            f"{context} must accept SAT and fail closed on production UNSAT"
        )
    return contract


def _validate_template(value: Any, context: str) -> list[str]:
    if type(value) is not list or not value:
        raise CampaignError(f"{context} must be a non-empty array")
    template: list[str] = []
    counts = {name: 0 for name in PLACEHOLDERS}
    formatter = string.Formatter()
    for index, raw_argument in enumerate(value):
        argument = require_string(raw_argument, f"{context}[{index}]")
        try:
            parsed = list(formatter.parse(argument))
        except ValueError as error:
            raise CampaignError(f"{context}[{index}] has invalid braces: {error}") from error
        for _, field_name, format_spec, conversion in parsed:
            if field_name is None:
                continue
            if field_name not in PLACEHOLDERS:
                raise CampaignError(
                    f"{context}[{index}] has unknown placeholder {field_name!r}"
                )
            if format_spec or conversion:
                raise CampaignError(
                    f"{context}[{index}] cannot use format specs or conversions"
                )
            counts[field_name] += 1
        template.append(argument)
    if template[0] != "{binary}":
        raise CampaignError(f"{context}[0] must be the literal '{{binary}}'")
    wrong_counts = {
        key: count
        for key, count in counts.items()
        if (key in {"binary", "instance"} and count != 1)
        or (key == "budget_s" and count > 1)
    }
    if wrong_counts:
        raise CampaignError(
            f"{context} needs binary and instance exactly once and budget_s at most once; "
            f"counts={wrong_counts!r}"
        )
    return template


def _format_budget(value: int | float) -> str:
    return str(value)


def _expand_argv(
    template: list[str], binary: Path, instance: Path, budget_s: int | float
) -> list[str]:
    values = {
        "binary": str(binary),
        "instance": str(instance),
        "budget_s": _format_budget(budget_s),
    }
    return [argument.format_map(values) for argument in template]


def _job_order(order: str, instance_index: int, solver_count: int) -> list[int]:
    if order == "abba":
        return [0, 1, 1, 0] if instance_index % 2 == 0 else [1, 0, 0, 1]
    offset = instance_index % solver_count
    return [(offset + position) % solver_count for position in range(solver_count)]


def build_jobs(
    instances: list[dict[str, Any]],
    instance_paths: tuple[Path, ...],
    solvers: list[dict[str, Any]],
    solver_paths: tuple[Path, ...],
    budgets: list[int | float],
    execution: dict[str, Any],
    output_directory: Path,
    run_selection: list[dict[str, str]] | None = None,
) -> tuple[Job, ...]:
    jobs: list[Job] = []
    base_environment = execution["environment"]
    cpu_ids = execution["cpu_ids"]
    order = execution["order"]
    selected_pairs = (
        {
            (selection["instance_id"], selection["solver_id"])
            for selection in run_selection
        }
        if run_selection is not None
        else None
    )
    sequence = 0
    for instance_index, instance in enumerate(instances):
        cpu_id = cpu_ids[instance_index % len(cpu_ids)]
        solver_order = _job_order(order, instance_index, len(solvers))
        if selected_pairs is not None:
            solver_order = [
                solver_index
                for solver_index in solver_order
                if (instance["id"], solvers[solver_index]["id"]) in selected_pairs
            ]
        for budget_s in budgets:
            repetitions = {solver_index: 0 for solver_index in range(len(solvers))}
            for solver_index in solver_order:
                solver = solvers[solver_index]
                environment = dict(base_environment)
                environment.update(solver["environment"])
                argv = _expand_argv(
                    solver["argv_template"],
                    solver_paths[solver_index],
                    instance_paths[instance_index],
                    budget_s,
                )
                evidence_path = None
                evidence = solver.get("evidence")
                if evidence is not None:
                    evidence_path = (
                        output_directory
                        / "production-evidence"
                        / f"run-{sequence:08d}.json"
                    )
                    argv.extend([evidence["argv_flag"], str(evidence_path)])
                jobs.append(
                    Job(
                        sequence=sequence,
                        instance_index=instance_index,
                        instance=instance,
                        solver_index=solver_index,
                        solver=solver,
                        budget_s=budget_s,
                        repetition=repetitions[solver_index],
                        cpu_id=cpu_id,
                        argv=argv,
                        environment=environment,
                        environment_sha256=sha256_bytes(canonical_bytes(environment)),
                        evidence_path=evidence_path,
                    )
                )
                repetitions[solver_index] += 1
                sequence += 1
    return tuple(jobs)


def load_and_validate_lock(path: Path) -> LockedCampaign:
    lock_path = Path(os.path.abspath(path))
    payload = read_json_strict(lock_path, "campaign lock")
    has_continuation = "continuation" in payload
    has_run_selection = "run_selection" in payload
    expected_top_level = TOP_LEVEL_KEYS | {
        key
        for key in ("shard", "runtime_binding", "continuation", "run_selection")
        if key in payload
    }
    require_exact_keys(payload, expected_top_level, "campaign lock")
    expected_schema = 2 if has_continuation else 1
    if (
        payload["schema_version"] != expected_schema
        or type(payload["schema_version"]) is not int
    ):
        raise CampaignError(
            f"campaign lock schema_version must be integer {expected_schema}"
        )
    require_string(payload["campaign_id"], "campaign_id")
    lock_digest = require_hash(payload["lock_sha256"], "lock_sha256")
    digest_payload = dict(payload)
    digest_payload["lock_sha256"] = ""
    actual_lock_digest = sha256_bytes(canonical_bytes(digest_payload))
    if actual_lock_digest != lock_digest:
        raise CampaignError(
            f"campaign lock hash drift: expected {lock_digest}, got {actual_lock_digest}"
        )
    require_string(payload["created_from_commit_time"], "created_from_commit_time")
    promotion_eligible = require_bool(
        payload["promotion_eligible"], "promotion_eligible"
    )
    if "shard" in payload:
        shard = require_exact_keys(payload["shard"], SHARD_KEYS, "shard")
        shard_index = require_int(shard["index"], "shard.index", minimum=0)
        shard_count = require_int(shard["count"], "shard.count", minimum=1)
        if shard_index >= shard_count:
            raise CampaignError("shard.index must be less than shard.count")
        parent_digest = require_hash(
            shard["parent_lock_sha256"], "shard.parent_lock_sha256"
        )
        if parent_digest == lock_digest:
            raise CampaignError("shard.parent_lock_sha256 cannot equal lock_sha256")
    if "runtime_binding" in payload:
        binding = require_exact_keys(
            payload["runtime_binding"],
            RUNTIME_BINDING_KEYS,
            "runtime_binding",
        )
        parent_digest = require_hash(
            binding["parent_lock_sha256"],
            "runtime_binding.parent_lock_sha256",
        )
        if parent_digest == lock_digest:
            raise CampaignError(
                "runtime_binding.parent_lock_sha256 cannot equal lock_sha256"
            )
        if binding["mechanism"] != "first_allowed_slurm_cpu":
            raise CampaignError("runtime_binding mechanism is not recognized")

    if has_continuation != has_run_selection:
        raise CampaignError(
            "continuation and run_selection must either both be present or absent"
        )

    spec = require_exact_keys(payload["spec"], SPEC_KEYS, "spec")
    spec_path = require_absolute_path(spec["path"], "spec.path")
    require_hash(spec["sha256"], "spec.sha256")

    repository = require_exact_keys(
        payload["repository"], REPOSITORY_KEYS, "repository"
    )
    repository_root = require_absolute_path(repository["root"], "repository.root")
    commit = require_string(repository["commit"], "repository.commit")
    if not HEX40_OR_64.fullmatch(commit):
        raise CampaignError("repository.commit must be a lowercase Git object id")
    require_string(repository["commit_time"], "repository.commit_time")
    repository_clean = require_bool(repository["clean"], "repository.clean")
    repository_promotion = require_bool(
        repository["promotion_eligible"], "repository.promotion_eligible"
    )
    if repository_promotion != repository_clean:
        raise CampaignError("repository.promotion_eligible must equal repository.clean")
    _path_under(spec_path, repository_root, "spec.path")

    host = require_exact_keys(payload["host"], HOST_KEYS, "host")
    for field in sorted(HOST_KEYS):
        require_string(host[field], f"host.{field}")

    corpus = require_exact_keys(payload["corpus"], CORPUS_KEYS, "corpus")
    require_string(corpus["id"], "corpus.id")
    manifest_path = require_absolute_path(
        corpus["manifest_path"], "corpus.manifest_path"
    )
    require_hash(corpus["manifest_sha256"], "corpus.manifest_sha256")
    corpus_root = require_absolute_path(corpus["root"], "corpus.root")
    taxonomy_path_value = corpus["taxonomy_path"]
    taxonomy_hash_value = corpus["taxonomy_sha256"]
    if taxonomy_path_value is None and taxonomy_hash_value is None:
        taxonomy_path = None
    elif taxonomy_path_value is not None and taxonomy_hash_value is not None:
        taxonomy_path = require_absolute_path(
            taxonomy_path_value, "corpus.taxonomy_path"
        )
        require_hash(taxonomy_hash_value, "corpus.taxonomy_sha256")
    else:
        raise CampaignError(
            "corpus.taxonomy_path and corpus.taxonomy_sha256 must both be null or set"
        )

    raw_instances = corpus["instances"]
    if type(raw_instances) is not list or not raw_instances:
        raise CampaignError("corpus.instances must be a non-empty array")
    instances: list[dict[str, Any]] = []
    instance_paths: list[Path] = []
    seen_instance_ids: set[str] = set()
    seen_relative_paths: set[str] = set()
    expected_instance_keys = INSTANCE_KEYS | (
        TAXONOMY_INSTANCE_KEYS if taxonomy_path is not None else set()
    )
    for index, raw_instance in enumerate(raw_instances):
        context = f"corpus.instances[{index}]"
        instance = require_exact_keys(raw_instance, expected_instance_keys, context)
        identifier = require_string(instance["id"], f"{context}.id")
        if identifier in seen_instance_ids:
            raise CampaignError(f"duplicate instance id {identifier!r}")
        relative_path = require_string(
            instance["relative_path"], f"{context}.relative_path"
        )
        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise CampaignError(f"{context}.relative_path must stay below corpus.root")
        if relative_path in seen_relative_paths:
            raise CampaignError(f"duplicate instance relative_path {relative_path!r}")
        instance_path = require_absolute_path(instance["path"], f"{context}.path")
        _path_under(instance_path, corpus_root, f"{context}.path")
        expected_path = Path(os.path.abspath(corpus_root / relative))
        if instance_path != expected_path:
            raise CampaignError(
                f"{context}.path does not equal corpus.root/relative_path"
            )
        require_hash(instance["sha256"], f"{context}.sha256")
        require_int(instance["bytes"], f"{context}.bytes", minimum=0)
        if instance["status"] not in {"sat", "unsat"}:
            raise CampaignError(f"{context}.status must be sat or unsat")
        if taxonomy_path is not None:
            for field in ("family", "lineage"):
                require_string(instance[field], f"{context}.{field}")
            require_hash(
                instance["normalized_sha256"], f"{context}.normalized_sha256"
            )
            if instance["split"] not in {"dev", "development", "holdout"}:
                raise CampaignError(
                    f"{context}.split must be dev, development, or holdout"
                )
        instances.append(instance)
        instance_paths.append(instance_path)
        seen_instance_ids.add(identifier)
        seen_relative_paths.add(relative_path)
    if instances != sorted(
        instances, key=lambda item: (item["relative_path"], item["id"])
    ):
        raise CampaignError("corpus.instances must be sorted by relative_path then id")

    solver_config = require_exact_keys(
        payload["solver_config"], SOLVER_CONFIG_KEYS, "solver_config"
    )
    solver_config_path = require_absolute_path(
        solver_config["path"], "solver_config.path"
    )
    require_hash(solver_config["sha256"], "solver_config.sha256")

    solver_release_lock = require_exact_keys(
        payload["solver_release_lock"],
        SOLVER_RELEASE_LOCK_KEYS,
        "solver_release_lock",
    )
    solver_release_lock_path = require_absolute_path(
        solver_release_lock["path"], "solver_release_lock.path"
    )
    _path_under(
        solver_release_lock_path,
        repository_root,
        "solver_release_lock.path",
    )
    require_hash(solver_release_lock["sha256"], "solver_release_lock.sha256")

    raw_solvers = payload["solvers"]
    if type(raw_solvers) is not list or not raw_solvers:
        raise CampaignError("solvers must be a non-empty array")
    solvers: list[dict[str, Any]] = []
    solver_paths: list[Path] = []
    seen_solver_ids: set[str] = set()
    for index, raw_solver in enumerate(raw_solvers):
        context = f"solvers[{index}]"
        solver_keys = SOLVER_KEYS | (
            {"evidence"}
            if type(raw_solver) is dict and "evidence" in raw_solver
            else set()
        )
        solver = require_exact_keys(raw_solver, solver_keys, context)
        identifier = require_string(solver["id"], f"{context}.id")
        if identifier in seen_solver_ids:
            raise CampaignError(f"duplicate solver id {identifier!r}")
        for field in ("comparator_id", "configuration", "version"):
            require_string(solver[field], f"{context}.{field}")
        solver_path = require_absolute_path(solver["binary"], f"{context}.binary")
        require_hash(solver["sha256"], f"{context}.sha256")
        solver["argv_template"] = _validate_template(
            solver["argv_template"], f"{context}.argv_template"
        )
        if has_continuation and any(
            "{budget_s}" in argument for argument in solver["argv_template"]
        ):
            raise CampaignError(
                f"{context}.argv_template is budget-dependent; "
                "timeout-only carry-forward is invalid"
            )
        version_output = solver["version_output"]
        version_hash = solver["version_output_sha256"]
        if version_output is None and version_hash is None:
            pass
        elif type(version_output) is str and version_hash is not None:
            require_hash(version_hash, f"{context}.version_output_sha256")
            actual_version_hash = sha256_bytes(version_output.encode("utf-8"))
            if actual_version_hash != version_hash:
                raise CampaignError(f"{context} version output hash drift")
        else:
            raise CampaignError(
                f"{context}.version_output and hash must both be null or set"
            )
        solver["environment"] = _validate_environment(
            solver["environment"], f"{context}.environment"
        )
        if "evidence" in solver:
            solver["evidence"] = _validate_evidence_contract(
                solver["evidence"], f"{context}.evidence"
            )
        solvers.append(solver)
        solver_paths.append(solver_path)
        seen_solver_ids.add(identifier)
    if [solver["id"] for solver in solvers] != sorted(seen_solver_ids):
        raise CampaignError("solvers must be sorted by id")

    run_selection: list[dict[str, str]] | None = None
    target_budget: int | float | None = None
    if has_continuation:
        continuation = require_exact_keys(
            payload["continuation"], CONTINUATION_KEYS, "continuation"
        )
        if continuation["mode"] != "timeout_only":
            raise CampaignError("continuation.mode must be timeout_only")
        for field in (
            "root_lock_sha256",
            "parent_lock_file_sha256",
            "parent_lock_sha256",
            "shard_bundle_sha256",
            "source_evidence_sha256",
            "selection_sha256",
            "runner_sha256",
        ):
            require_hash(continuation[field], f"continuation.{field}")
        for field in (
            "parent_lock_path",
            "shard_lock_directory",
            "shard_results_root",
            "runner_path",
        ):
            require_absolute_path(continuation[field], f"continuation.{field}")
        source_budget = require_number(
            continuation["source_budget_s"],
            "continuation.source_budget_s",
            minimum=0.001,
        )
        target_budget = require_number(
            continuation["target_budget_s"],
            "continuation.target_budget_s",
            minimum=0.001,
        )
        if target_budget <= source_budget:
            raise CampaignError("continuation target budget must exceed source budget")
        if continuation["source_evidence_sha256"] != continuation["shard_bundle_sha256"]:
            raise CampaignError(
                "continuation source evidence and shard bundle hashes disagree"
            )
        selected_instances = require_int(
            continuation["selected_instances"],
            "continuation.selected_instances",
            minimum=1,
        )
        selected_runs = require_int(
            continuation["selected_runs"],
            "continuation.selected_runs",
            minimum=1,
        )
        raw_selection = payload["run_selection"]
        if type(raw_selection) is not list or not raw_selection:
            raise CampaignError("run_selection must be a non-empty array")
        run_selection = []
        seen_run_pairs: set[tuple[str, str]] = set()
        instance_ordinals = {
            instance["id"]: index for index, instance in enumerate(instances)
        }
        solver_ordinals = {
            solver["id"]: index for index, solver in enumerate(solvers)
        }
        previous_ordinal: tuple[int, int] | None = None
        selected_instance_ids: set[str] = set()
        for index, raw_selection_item in enumerate(raw_selection):
            context = f"run_selection[{index}]"
            item = require_exact_keys(
                raw_selection_item, RUN_SELECTION_KEYS, context
            )
            instance_id = require_string(
                item["instance_id"], f"{context}.instance_id"
            )
            solver_id = require_string(item["solver_id"], f"{context}.solver_id")
            if instance_id not in instance_ordinals:
                raise CampaignError(
                    f"{context} references unknown instance {instance_id!r}"
                )
            if solver_id not in solver_ordinals:
                raise CampaignError(
                    f"{context} references unknown solver {solver_id!r}"
                )
            pair = (instance_id, solver_id)
            if pair in seen_run_pairs:
                raise CampaignError(f"duplicate run_selection pair {pair!r}")
            ordinal = (instance_ordinals[instance_id], solver_ordinals[solver_id])
            if previous_ordinal is not None and ordinal <= previous_ordinal:
                raise CampaignError(
                    "run_selection must follow corpus instance and solver order"
                )
            previous_ordinal = ordinal
            seen_run_pairs.add(pair)
            selected_instance_ids.add(instance_id)
            run_selection.append({"instance_id": instance_id, "solver_id": solver_id})
        if selected_runs != len(run_selection):
            raise CampaignError(
                "continuation.selected_runs disagrees with run_selection"
            )
        if selected_instances != len(selected_instance_ids):
            raise CampaignError(
                "continuation.selected_instances disagrees with run_selection"
            )
        if selected_instance_ids != set(instance_ordinals):
            raise CampaignError(
                "every continuation corpus instance must have a selected run"
            )
        actual_selection_hash = sha256_bytes(canonical_bytes(run_selection))
        if actual_selection_hash != continuation["selection_sha256"]:
            raise CampaignError("continuation selection SHA-256 mismatch")

    raw_budgets = payload["budgets_s"]
    if type(raw_budgets) is not list or not raw_budgets:
        raise CampaignError("budgets_s must be a non-empty array")
    budgets: list[int | float] = []
    for index, value in enumerate(raw_budgets):
        budgets.append(require_number(value, f"budgets_s[{index}]", minimum=0.001))
    if any(left >= right for left, right in zip(budgets, budgets[1:])):
        raise CampaignError("budgets_s must be strictly increasing")
    if has_continuation and budgets != [target_budget]:
        raise CampaignError(
            "continuation lock budgets_s must contain only target_budget_s"
        )

    execution = require_exact_keys(
        payload["execution"], EXECUTION_KEYS, "execution"
    )
    if execution["resource_model"] != "single_core_cold_process":
        raise CampaignError(
            "execution.resource_model must be single_core_cold_process"
        )
    cpu_ids = execution["cpu_ids"]
    if type(cpu_ids) is not list or not cpu_ids:
        raise CampaignError("execution.cpu_ids must be a non-empty array")
    validated_cpu_ids = [
        require_int(value, f"execution.cpu_ids[{index}]", minimum=0)
        for index, value in enumerate(cpu_ids)
    ]
    if len(set(validated_cpu_ids)) != len(validated_cpu_ids):
        raise CampaignError("execution.cpu_ids must be unique")
    execution["cpu_ids"] = validated_cpu_ids
    if "runtime_binding" in payload:
        binding_cpu_ids = payload["runtime_binding"]["cpu_ids"]
        if binding_cpu_ids != validated_cpu_ids:
            raise CampaignError(
                "runtime_binding.cpu_ids must equal execution.cpu_ids"
            )
    require_int(execution["memory_bytes"], "execution.memory_bytes", minimum=1)
    if execution["order"] not in {"abba", "balanced_latin_square"}:
        raise CampaignError(
            "execution.order must be abba or balanced_latin_square"
        )
    if execution["order"] == "abba" and len(solvers) != 2:
        raise CampaignError("execution.order abba requires exactly two solvers")
    if has_continuation and execution["order"] != "balanced_latin_square":
        raise CampaignError(
            "continuation execution.order must be balanced_latin_square"
        )
    execution["environment"] = _validate_environment(
        execution["environment"], "execution.environment"
    )
    require_number(
        execution["timeout_grace_s"],
        "execution.timeout_grace_s",
        minimum=0.0,
    )

    output = require_exact_keys(payload["output"], OUTPUT_KEYS, "output")
    output_directory = require_absolute_path(
        output["directory"], "output.directory"
    )
    journal_path = _output_path(output_directory, output["journal"], "output.journal")
    raw_path = _output_path(output_directory, output["raw"], "output.raw")
    summary_path = _output_path(
        output_directory, output["summary"], "output.summary"
    )
    output_paths = {journal_path, raw_path, summary_path}
    if len(output_paths) != 3:
        raise CampaignError("output journal, raw, and summary paths must be distinct")

    expected_promotion = (
        False
        if has_continuation
        else bool(repository_promotion and taxonomy_path is not None)
    )
    if promotion_eligible != expected_promotion:
        raise CampaignError(
            "promotion_eligible must equal repository eligibility plus taxonomy"
        )

    jobs = build_jobs(
        instances,
        tuple(instance_paths),
        solvers,
        tuple(solver_paths),
        budgets,
        execution,
        output_directory,
        run_selection,
    )
    return LockedCampaign(
        lock_path=lock_path,
        payload=payload,
        repository_root=repository_root,
        spec_path=spec_path,
        manifest_path=manifest_path,
        taxonomy_path=taxonomy_path,
        solver_config_path=solver_config_path,
        solver_release_lock_path=solver_release_lock_path,
        corpus_root=corpus_root,
        output_directory=output_directory,
        journal_path=journal_path,
        raw_path=raw_path,
        summary_path=summary_path,
        instance_paths=tuple(instance_paths),
        solver_paths=tuple(solver_paths),
        jobs=jobs,
    )


def _file_fingerprint(path: Path) -> tuple[int, int, int, int, int, int]:
    try:
        metadata = path.stat()
    except OSError as error:
        raise CampaignError(f"cannot stat frozen artifact {path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise CampaignError(f"frozen artifact is not a regular file: {path}")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _verify_hash(
    path: Path,
    expected: str,
    context: str,
    snapshots: dict[Path, ArtifactSnapshot],
) -> None:
    fingerprint = _file_fingerprint(path)
    actual = sha256_file(path)
    if actual != expected:
        raise CampaignError(
            f"{context} hash drift for {path}: expected {expected}, got {actual}"
        )
    existing = snapshots.get(path)
    if existing is not None and existing.fingerprint != fingerprint:
        raise CampaignError(f"frozen artifact aliases changing files: {path}")
    snapshots[path] = ArtifactSnapshot(path, fingerprint)


def _git(repository: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            env={
                "PATH": os.environ.get("PATH", os.defpath),
                "LANG": "C",
                "LC_ALL": "C",
            },
        )
    except OSError as error:
        raise CampaignError(f"cannot execute git: {error}") from error
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip()
        raise CampaignError(f"git {' '.join(arguments)} failed: {message}")
    return completed.stdout.strip()


def verify_repository(campaign: LockedCampaign) -> None:
    repository = campaign.payload["repository"]
    actual_root = Path(
        _git(campaign.repository_root, "rev-parse", "--show-toplevel")
    ).resolve()
    if actual_root != campaign.repository_root.resolve():
        raise CampaignError(
            f"repository root drift: expected {campaign.repository_root}, got {actual_root}"
        )
    actual_commit = _git(campaign.repository_root, "rev-parse", "HEAD")
    if actual_commit != repository["commit"]:
        raise CampaignError(
            f"repository commit drift: expected {repository['commit']}, got {actual_commit}"
        )
    actual_commit_time = _git(
        campaign.repository_root, "show", "-s", "--format=%cI", "HEAD"
    )
    if actual_commit_time != repository["commit_time"]:
        raise CampaignError("repository commit_time does not match locked commit")
    if actual_commit_time != campaign.payload["created_from_commit_time"]:
        raise CampaignError("created_from_commit_time does not match locked commit")
    status = _git(
        campaign.repository_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=no",
    )
    actual_clean = not bool(status)
    if actual_clean != repository["clean"]:
        raise CampaignError(
            f"repository cleanliness drift: expected clean={repository['clean']}, "
            f"got clean={actual_clean}"
        )


def verify_frozen_artifacts(campaign: LockedCampaign) -> dict[Path, ArtifactSnapshot]:
    verify_repository(campaign)
    snapshots: dict[Path, ArtifactSnapshot] = {}
    snapshots[campaign.lock_path] = ArtifactSnapshot(
        campaign.lock_path, _file_fingerprint(campaign.lock_path)
    )
    payload = campaign.payload
    _verify_hash(
        campaign.spec_path, payload["spec"]["sha256"], "spec", snapshots
    )
    _verify_hash(
        campaign.manifest_path,
        payload["corpus"]["manifest_sha256"],
        "manifest",
        snapshots,
    )
    if campaign.taxonomy_path is not None:
        _verify_hash(
            campaign.taxonomy_path,
            payload["corpus"]["taxonomy_sha256"],
            "taxonomy",
            snapshots,
        )
    _verify_hash(
        campaign.solver_config_path,
        payload["solver_config"]["sha256"],
        "solver config",
        snapshots,
    )
    _verify_hash(
        campaign.solver_release_lock_path,
        payload["solver_release_lock"]["sha256"],
        "solver release lock",
        snapshots,
    )
    if "continuation" in payload:
        continuation = payload["continuation"]
        parent_lock_path = Path(continuation["parent_lock_path"])
        _verify_hash(
            parent_lock_path,
            continuation["parent_lock_file_sha256"],
            "continuation parent lock",
            snapshots,
        )
        parent_lock = read_json_strict(parent_lock_path, "continuation parent lock")
        declared_parent_hash = require_hash(
            parent_lock.get("lock_sha256"),
            "continuation parent lock lock_sha256",
        )
        actual_parent_hash = sha256_bytes(
            canonical_bytes({**parent_lock, "lock_sha256": ""})
        )
        if declared_parent_hash != actual_parent_hash:
            raise CampaignError("continuation parent lock self-hash mismatch")
        if declared_parent_hash != continuation["parent_lock_sha256"]:
            raise CampaignError("continuation parent lock lineage mismatch")
        expected_root_hash = (
            parent_lock["continuation"]["root_lock_sha256"]
            if isinstance(parent_lock.get("continuation"), dict)
            else declared_parent_hash
        )
        if continuation["root_lock_sha256"] != expected_root_hash:
            raise CampaignError("continuation root lock lineage mismatch")
        runner_path = Path(continuation["runner_path"])
        actual_runner_path = Path(__file__).resolve()
        if runner_path.resolve() != actual_runner_path:
            raise CampaignError(
                f"continuation requires runner {runner_path}, got {actual_runner_path}"
            )
        _verify_hash(
            actual_runner_path,
            continuation["runner_sha256"],
            "continuation runner",
            snapshots,
        )
    for index, instance_path in enumerate(campaign.instance_paths):
        instance = payload["corpus"]["instances"][index]
        _verify_hash(
            instance_path,
            instance["sha256"],
            f"instance {instance['relative_path']!r}",
            snapshots,
        )
        if instance_path.stat().st_size != instance["bytes"]:
            raise CampaignError(
                f"instance size drift for {instance['relative_path']!r}"
            )
    for index, solver_path in enumerate(campaign.solver_paths):
        solver = payload["solvers"][index]
        _verify_hash(
            solver_path,
            solver["sha256"],
            f"solver {solver['id']!r}",
            snapshots,
        )
        if not os.access(solver_path, os.X_OK):
            raise CampaignError(f"solver is not executable: {solver_path}")
    return snapshots


def assert_unchanged(snapshot: ArtifactSnapshot) -> None:
    if _file_fingerprint(snapshot.path) != snapshot.fingerprint:
        raise CampaignError(f"frozen artifact changed during execution: {snapshot.path}")


def assert_all_unchanged(snapshots: dict[Path, ArtifactSnapshot]) -> None:
    for path in sorted(snapshots, key=str):
        assert_unchanged(snapshots[path])


def enforcement_capabilities(campaign: LockedCampaign) -> dict[str, Any]:
    if os.name != "posix" or not hasattr(os, "killpg") or not hasattr(os, "wait4"):
        raise CampaignError(
            "this runner requires POSIX process groups and os.wait4 accounting"
        )
    execution = campaign.payload["execution"]
    linux = sys.platform.startswith("linux")
    affinity_available = bool(
        linux
        and hasattr(os, "sched_setaffinity")
        and hasattr(os, "sched_getaffinity")
    )
    allowed_cpus: list[int] | None = None
    affinity_enforced = False
    if linux:
        if not affinity_available:
            raise CampaignError("Linux CPU affinity is unavailable")
        allowed = set(os.sched_getaffinity(0))
        configured = set(execution["cpu_ids"])
        unavailable = sorted(configured - allowed)
        if unavailable:
            raise CampaignError(
                f"configured CPU ids are outside this process affinity: {unavailable!r}"
            )
        allowed_cpus = sorted(allowed)
        affinity_enforced = True

    rlimit_as_api_present = bool(
        resource is not None and hasattr(resource, "RLIMIT_AS")
    )
    rlimit_as_available = False
    rlimit_as_enforced = False
    if rlimit_as_api_present:
        assert resource is not None
        _, hard = resource.getrlimit(resource.RLIMIT_AS)
        requested = execution["memory_bytes"]
        if hard != resource.RLIM_INFINITY and requested > hard:
            raise CampaignError(
                f"memory_bytes {requested} exceeds hard RLIMIT_AS {hard}"
            )
        probe_pid = os.fork()
        if probe_pid == 0:  # pragma: no branch - only the child follows this path.
            try:
                resource.setrlimit(resource.RLIMIT_AS, (requested, hard))
            except (OSError, ValueError):
                os._exit(1)
            os._exit(0)
        _, probe_status = os.waitpid(probe_pid, 0)
        rlimit_as_available = os.waitstatus_to_exitcode(probe_status) == 0
        rlimit_as_enforced = rlimit_as_available

    cgroup_v2 = Path("/sys/fs/cgroup/cgroup.controllers").is_file()
    cgroup_v1 = linux and Path("/proc/self/cgroup").is_file() and not cgroup_v2
    return {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "cold_process": {"enforced": True, "mechanism": "new subprocess per solve"},
        "sequential": {"enforced": True, "maximum_concurrent_solves": 1},
        "process_group": {
            "enforced": True,
            "mechanism": "start_new_session and killpg",
        },
        "cpu_affinity": {
            "configured_cpu_ids": execution["cpu_ids"],
            "platform_support": affinity_available,
            "enforced": affinity_enforced,
            "mechanism": "sched_setaffinity" if affinity_enforced else None,
            "runner_allowed_cpu_ids": allowed_cpus,
            "one_cpu_per_solve": affinity_enforced,
        },
        "address_space_limit": {
            "requested_bytes": execution["memory_bytes"],
            "api_present": rlimit_as_api_present,
            "platform_support": rlimit_as_available,
            "enforced": rlimit_as_enforced,
            "mechanism": "RLIMIT_AS" if rlimit_as_enforced else None,
            "is_rss_limit": False,
        },
        "accounting": {
            "child_cpu": True,
            "max_rss": True,
            "mechanism": "wait4/rusage",
        },
        "cgroup": {
            "detected": cgroup_v2 or cgroup_v1,
            "version": 2 if cgroup_v2 else (1 if cgroup_v1 else None),
            "enforced": False,
        },
        "benchexec": {
            "detected": shutil.which("benchexec") is not None,
            "used": False,
        },
        "cgroup_or_benchexec_equivalent": False,
    }


def _preexec_setup(
    cpu_id: int,
    memory_bytes: int,
    enforce_affinity: bool,
    enforce_address_space: bool,
) -> Callable[[], None]:

    def setup() -> None:
        if enforce_affinity:
            os.sched_setaffinity(0, {cpu_id})
        if enforce_address_space:
            assert resource is not None
            _, hard = resource.getrlimit(resource.RLIMIT_AS)
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, hard))

    return setup


def _send_group_signal(process_group: int, sent_signal: signal.Signals) -> None:
    try:
        os.killpg(process_group, sent_signal)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise CampaignError(
            f"cannot signal process group {process_group}: {error}"
        ) from error


def _wait4_nohang(pid: int) -> tuple[int, Any] | None:
    try:
        waited_pid, status_value, usage = os.wait4(pid, os.WNOHANG)
    except InterruptedError:
        return None
    if waited_pid == 0:
        return None
    return status_value, usage


def _wait4_blocking(pid: int) -> tuple[int, Any]:
    while True:
        try:
            waited_pid, status_value, usage = os.wait4(pid, 0)
        except InterruptedError:
            continue
        if waited_pid == pid:
            return status_value, usage


def _wait_with_timeout(
    process: subprocess.Popen[bytes], timeout_s: float, grace_s: float
) -> tuple[int, Any, bool]:
    deadline = time.monotonic() + timeout_s
    while True:
        waited = _wait4_nohang(process.pid)
        if waited is not None:
            return waited[0], waited[1], False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.01, remaining))

    _send_group_signal(process.pid, signal.SIGTERM)
    status_and_usage: tuple[int, Any] | None = None
    grace_deadline = time.monotonic() + grace_s
    while time.monotonic() < grace_deadline:
        if status_and_usage is None:
            status_and_usage = _wait4_nohang(process.pid)
        time.sleep(min(0.01, max(0.0, grace_deadline - time.monotonic())))
    # Kill the group even if its leader already exited after SIGTERM.  Children
    # can remain in the process group after the leader has been reaped.
    _send_group_signal(process.pid, signal.SIGKILL)
    if status_and_usage is None:
        status_and_usage = _wait4_blocking(process.pid)
    return status_and_usage[0], status_and_usage[1], True


def _rusage_values(usage: Any) -> tuple[float, float, int]:
    user = float(usage.ru_utime)
    system = float(usage.ru_stime)
    raw_rss = int(usage.ru_maxrss)
    max_rss_bytes = raw_rss * 1024 if sys.platform.startswith("linux") else raw_rss
    return user, system, max_rss_bytes


def _inspect_stdout(path: Path) -> tuple[str, int, str | None, str]:
    digest = hashlib.sha256()
    byte_count = 0
    prefix = bytearray()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
            byte_count += len(block)
            if len(prefix) <= 128:
                prefix.extend(block[: 129 - len(prefix)])
    if byte_count == 0:
        return digest.hexdigest(), byte_count, None, "missing"
    if byte_count > 128:
        return digest.hexdigest(), byte_count, None, "malformed"
    try:
        tokens = bytes(prefix).decode("ascii").split()
    except UnicodeDecodeError:
        return digest.hexdigest(), byte_count, None, "malformed"
    if len(tokens) == 1 and tokens[0] in RESULT_TOKENS:
        return digest.hexdigest(), byte_count, tokens[0], "valid"
    return digest.hexdigest(), byte_count, None, "malformed"


def _hash_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
            byte_count += len(block)
    return digest.hexdigest(), byte_count


def _production_evidence_binding(
    job: Job,
    output_directory: Path,
    repository_revision: str,
    result_token: str | None,
) -> dict[str, Any] | None:
    contract = job.solver.get("evidence")
    if contract is None:
        if job.evidence_path is not None:
            raise CampaignError("job has an evidence path without a locked contract")
        return None
    if job.evidence_path is None:
        raise CampaignError("evidence-enabled job lacks an output path")
    path = job.evidence_path
    if not path.exists():
        if result_token in {"sat", "unsat"}:
            raise CampaignError(
                f"decisive result {result_token!r} omitted production evidence for "
                f"{job.instance['relative_path']!r}"
            )
        return None
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CampaignError(f"cannot resolve production evidence {path}: {error}") from error
    if resolved != path:
        raise CampaignError(f"production evidence path was redirected: {path}")
    _path_under(resolved, output_directory, "production evidence path")
    payload = read_json_strict(resolved, "production evidence")
    require_exact_keys(
        payload,
        {
            "schema",
            "status",
            "backend_status",
            "source",
            "solver",
            "model",
            "limitations",
        },
        "production evidence",
    )
    if payload["schema"] != contract["schema"]:
        raise CampaignError("production evidence schema differs from the solver lock")
    status = require_string(payload["status"], "production evidence status")
    backend_status = require_string(
        payload["backend_status"], "production evidence backend_status"
    )
    if status not in {"sat", "unsupported"}:
        raise CampaignError("production evidence has invalid status")
    if backend_status not in {"sat", "unsat", "unsupported"}:
        raise CampaignError("production evidence has invalid backend_status")
    if result_token in {"sat", "unsat"}:
        if result_token not in contract["accepted_decisive_statuses"]:
            raise CampaignError(
                f"production evidence contract does not accept decisive {result_token!r}"
            )
        if status != result_token or backend_status != result_token:
            raise CampaignError("production evidence status differs from stdout")

    source = require_exact_keys(
        payload["source"], {"path", "sha256", "bytes"}, "production evidence source"
    )
    source_sha256 = require_hash(
        source["sha256"], "production evidence source.sha256"
    )
    if source_sha256 != job.instance["sha256"]:
        raise CampaignError("production evidence source hash differs from the lock")
    if (
        require_int(source["bytes"], "production evidence source.bytes", minimum=0)
        != job.instance["bytes"]
    ):
        raise CampaignError("production evidence source byte count differs from the lock")
    require_string(source["path"], "production evidence source.path")

    solver = require_exact_keys(
        payload["solver"],
        {
            "package_version",
            "revision",
            "dirty",
            "backend",
            "config",
            "config_sha256",
        },
        "production evidence solver",
    )
    revision = require_string(solver["revision"], "production evidence solver.revision")
    if revision != repository_revision:
        raise CampaignError(
            "production evidence revision mismatch: "
            f"expected {repository_revision}, got {revision}"
        )
    if require_bool(solver["dirty"], "production evidence solver.dirty"):
        raise CampaignError("production evidence was emitted by a dirty build")
    require_string(solver["package_version"], "production evidence package version")
    require_string(solver["backend"], "production evidence backend")
    config = _validate_environment(solver["config"], "production evidence solver.config")
    runtime_config_sha256 = require_hash(
        solver["config_sha256"], "production evidence solver.config_sha256"
    )
    if runtime_config_sha256 != sha256_bytes(canonical_bytes(config)):
        raise CampaignError("production evidence runtime config hash mismatch")
    digest, byte_count = _hash_and_size(resolved)
    return {
        "path": resolved.relative_to(output_directory).as_posix(),
        "sha256": digest,
        "bytes": byte_count,
        "schema": payload["schema"],
        "source_sha256": source_sha256,
        "solver_revision": revision,
        "solver_configuration": job.solver["configuration"],
        "solver_config_sha256": sha256_bytes(canonical_bytes(job.solver)),
        "solver_runtime_config_sha256": runtime_config_sha256,
        "status": status,
        "backend_status": backend_status,
    }


def run_job(
    job: Job,
    invocation: int,
    lock_sha256: str,
    output_directory: Path,
    repository_revision: str,
    memory_bytes: int,
    grace_s: float,
    enforce_affinity: bool,
    enforce_address_space: bool,
) -> dict[str, Any]:
    if job.evidence_path is not None and job.evidence_path.exists():
        raise CampaignError(
            f"refusing to reuse production evidence path {job.evidence_path}"
        )
    stdout_fd, stdout_name = tempfile.mkstemp(
        prefix=".locked-stdout-", dir=output_directory
    )
    stderr_fd, stderr_name = tempfile.mkstemp(
        prefix=".locked-stderr-", dir=output_directory
    )
    stdout_path = Path(stdout_name)
    stderr_path = Path(stderr_name)
    process: subprocess.Popen[bytes] | None = None
    started_at = utc_now()
    start = time.monotonic()
    timed_out = False
    exit_code: int | None = None
    termination_cause = "spawn_error"
    termination_signal: int | None = None
    spawn_error: str | None = None
    child_user: float | None = None
    child_system: float | None = None
    max_rss_bytes: int | None = None
    try:
        try:
            process = subprocess.Popen(
                job.argv,
                stdin=subprocess.DEVNULL,
                stdout=stdout_fd,
                stderr=stderr_fd,
                env=job.environment,
                close_fds=True,
                start_new_session=True,
                preexec_fn=_preexec_setup(
                    job.cpu_id,
                    memory_bytes,
                    enforce_affinity,
                    enforce_address_space,
                ),
            )
        except subprocess.SubprocessError as error:
            raise CampaignError(
                f"failed to establish child resource controls: {error}"
            ) from error
        except OSError as error:
            spawn_error = f"{type(error).__name__}: {error}"
        finally:
            os.close(stdout_fd)
            os.close(stderr_fd)

        if process is not None:
            try:
                status_value, usage, timed_out = _wait_with_timeout(
                    process, float(job.budget_s), grace_s
                )
            except BaseException:
                _send_group_signal(process.pid, signal.SIGKILL)
                try:
                    status_value, _ = _wait4_blocking(process.pid)
                    process.returncode = os.waitstatus_to_exitcode(status_value)
                except ChildProcessError:
                    pass
                raise
            exit_code = os.waitstatus_to_exitcode(status_value)
            process.returncode = exit_code
            child_user, child_system, max_rss_bytes = _rusage_values(usage)
            termination_signal = -exit_code if exit_code < 0 else None
            if timed_out:
                termination_cause = "timeout"
            elif exit_code < 0:
                termination_cause = "signal"
            else:
                termination_cause = "exit"
        wall_time_s = time.monotonic() - start
        finished_at = utc_now()
        stdout_hash, stdout_bytes, result_token, result_status = _inspect_stdout(
            stdout_path
        )
        stderr_hash, stderr_bytes = _hash_and_size(stderr_path)
        child_cpu = (
            child_user + child_system
            if child_user is not None and child_system is not None
            else None
        )
        evidence_binding = _production_evidence_binding(
            job, output_directory, repository_revision, result_token
        )
        record = {
            "record_type": "run",
            "schema_version": 1,
            "lock_sha256": lock_sha256,
            "invocation": invocation,
            "sequence": job.sequence,
            "key": job.key,
            "instance_id": job.instance["id"],
            "relative_path": job.instance["relative_path"],
            "instance_sha256": job.instance["sha256"],
            "expected_status": job.instance["status"],
            "family": job.instance.get("family"),
            "solver_id": job.solver["id"],
            "solver_sha256": job.solver["sha256"],
            "solver_version": job.solver["version"],
            "budget_s": job.budget_s,
            "repetition": job.repetition,
            "cpu_id": job.cpu_id,
            "argv": job.argv,
            "environment_sha256": job.environment_sha256,
            "pid": process.pid if process is not None else None,
            "started_at": started_at,
            "finished_at": finished_at,
            "wall_time_s": wall_time_s,
            "child_user_time_s": child_user,
            "child_system_time_s": child_system,
            "child_cpu_time_s": child_cpu,
            "max_rss_bytes": max_rss_bytes,
            "exit_code": exit_code,
            "termination_cause": termination_cause,
            "termination_signal": termination_signal,
            "timed_out": timed_out,
            "spawn_error": spawn_error,
            "stdout_sha256": stdout_hash,
            "stdout_bytes": stdout_bytes,
            "stderr_sha256": stderr_hash,
            "stderr_bytes": stderr_bytes,
            "result_token": result_token,
            "result_token_status": result_status,
        }
        if "evidence" in job.solver:
            record["production_evidence"] = evidence_binding
        return record
    finally:
        for temporary in (stdout_path, stderr_path):
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _record_digest(record: dict[str, Any]) -> str:
    unhashed = dict(record)
    unhashed.pop("record_sha256", None)
    return sha256_bytes(canonical_bytes(unhashed))


def _run_key_bytes(record: dict[str, Any]) -> bytes:
    key = record.get("key")
    require_exact_keys(
        key,
        {"instance_id", "solver_id", "budget_s", "repetition"},
        "journal run key",
    )
    return canonical_bytes(key)


def _same_json(left: Any, right: Any) -> bool:
    return canonical_bytes(left) == canonical_bytes(right)


def _validate_recorded_production_evidence(
    value: Any, job: Job, result_token: str | None, context: str
) -> None:
    if value is None:
        if result_token in {"sat", "unsat"}:
            raise CampaignError(f"{context} is missing for a decisive result")
        return
    binding = require_exact_keys(value, PRODUCTION_EVIDENCE_KEYS, context)
    require_string(binding["path"], f"{context}.path")
    require_hash(binding["sha256"], f"{context}.sha256")
    require_int(binding["bytes"], f"{context}.bytes", minimum=1)
    require_hash(binding["source_sha256"], f"{context}.source_sha256")
    require_hash(binding["solver_config_sha256"], f"{context}.solver_config_sha256")
    require_hash(
        binding["solver_runtime_config_sha256"],
        f"{context}.solver_runtime_config_sha256",
    )
    if binding["source_sha256"] != job.instance["sha256"]:
        raise CampaignError(f"{context} source hash differs from the job")
    if binding["solver_configuration"] != job.solver["configuration"]:
        raise CampaignError(f"{context} solver configuration differs from the job")
    if binding["solver_config_sha256"] != sha256_bytes(canonical_bytes(job.solver)):
        raise CampaignError(f"{context} solver config hash differs from the job")
    contract = job.solver["evidence"]
    if binding["schema"] != contract["schema"]:
        raise CampaignError(f"{context} schema differs from the job")
    if binding["status"] not in {"sat", "unsupported"}:
        raise CampaignError(f"{context} has invalid status")
    if binding["backend_status"] not in {"sat", "unsat", "unsupported"}:
        raise CampaignError(f"{context} has invalid backend status")
    if result_token in {"sat", "unsat"} and (
        result_token not in contract["accepted_decisive_statuses"]
        or binding["status"] != result_token
        or binding["backend_status"] != result_token
    ):
        raise CampaignError(f"{context} does not certify the decisive result")


def validate_run_record(record: dict[str, Any], job: Job, invocations: set[int]) -> None:
    expected_keys = RUN_RECORD_KEYS | (
        {"production_evidence"} if "evidence" in job.solver else set()
    )
    require_exact_keys(record, expected_keys, "journal run record")
    invocation = require_int(record["invocation"], "journal run invocation", minimum=0)
    if invocation not in invocations:
        raise CampaignError("journal run references an unknown invocation")
    expected_static = {
        "sequence": job.sequence,
        "key": job.key,
        "instance_id": job.instance["id"],
        "relative_path": job.instance["relative_path"],
        "instance_sha256": job.instance["sha256"],
        "expected_status": job.instance["status"],
        "family": job.instance.get("family"),
        "solver_id": job.solver["id"],
        "solver_sha256": job.solver["sha256"],
        "solver_version": job.solver["version"],
        "budget_s": job.budget_s,
        "repetition": job.repetition,
        "cpu_id": job.cpu_id,
        "argv": job.argv,
        "environment_sha256": job.environment_sha256,
    }
    for field, expected in expected_static.items():
        if not _same_json(record[field], expected):
            raise CampaignError(
                f"journal run sequence {job.sequence} has drifted field {field!r}"
            )
    for field in ("started_at", "finished_at"):
        require_string(record[field], f"journal run {field}")
    for field in (
        "wall_time_s",
        "child_user_time_s",
        "child_system_time_s",
        "child_cpu_time_s",
    ):
        if record[field] is not None:
            require_number(record[field], f"journal run {field}", minimum=0.0)
    if record["max_rss_bytes"] is not None:
        require_int(record["max_rss_bytes"], "journal run max_rss_bytes", minimum=0)
    for field in ("pid", "exit_code", "termination_signal"):
        if record[field] is not None and type(record[field]) is not int:
            raise CampaignError(f"journal run {field} must be an integer or null")
    if record["termination_cause"] not in {"exit", "signal", "timeout", "spawn_error"}:
        raise CampaignError("journal run has invalid termination_cause")
    require_bool(record["timed_out"], "journal run timed_out")
    if record["spawn_error"] is not None:
        require_string(record["spawn_error"], "journal run spawn_error")
    for field in ("stdout_sha256", "stderr_sha256"):
        require_hash(record[field], f"journal run {field}")
    for field in ("stdout_bytes", "stderr_bytes"):
        require_int(record[field], f"journal run {field}", minimum=0)
    if record["result_token"] is not None and record["result_token"] not in RESULT_TOKENS:
        raise CampaignError("journal run has invalid result_token")
    if record["result_token_status"] not in {"valid", "missing", "malformed"}:
        raise CampaignError("journal run has invalid result_token_status")
    if (record["result_token"] is None) == (record["result_token_status"] == "valid"):
        raise CampaignError("journal run result token and status disagree")
    if "evidence" in job.solver:
        _validate_recorded_production_evidence(
            record["production_evidence"],
            job,
            record["result_token"],
            "journal run production_evidence",
        )


class Journal:
    def __init__(self, path: Path, lock_sha256: str, jobs: tuple[Job, ...]):
        self.path = path
        self.lock_sha256 = lock_sha256
        self.jobs = jobs
        self.fd: int | None = None
        self.last_hash: str | None = None
        self.records: list[dict[str, Any]] = []
        self.invocations: list[dict[str, Any]] = []
        self.runs: list[dict[str, Any]] = []

    def __enter__(self) -> "Journal":
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            self.fd = os.open(self.path, flags, 0o600)
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            raise CampaignError(f"journal is locked by another runner: {self.path}") from error
        except OSError as error:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            raise CampaignError(f"cannot open journal {self.path}: {error}") from error
        self._load()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None

    def _read_all(self) -> bytes:
        assert self.fd is not None
        os.lseek(self.fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while True:
            block = os.read(self.fd, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        return b"".join(chunks)

    def _load(self) -> None:
        raw = self._read_all()
        if not raw:
            return
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CampaignError(f"journal is not UTF-8: {error}") from error
        if not text.endswith("\n"):
            raise CampaignError("journal ends with a partial record; refuse truncation")
        seen_run_keys: set[bytes] = set()
        seen_invocations: set[int] = set()
        last_hash: str | None = None
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line:
                raise CampaignError(f"journal {self.path}:{line_number} is blank")
            value = parse_json_strict(line, f"journal {self.path}:{line_number}")
            if type(value) is not dict:
                raise CampaignError(
                    f"journal {self.path}:{line_number} must be an object"
                )
            record = value
            if record.get("record_type") == "run":
                key_bytes = _run_key_bytes(record)
                if key_bytes in seen_run_keys:
                    raise CampaignError(
                        f"journal {self.path}:{line_number} has duplicate run key"
                    )
            if record.get("previous_record_sha256") != last_hash:
                raise CampaignError(
                    f"journal {self.path}:{line_number} breaks the hash chain"
                )
            record_hash = require_hash(
                record.get("record_sha256"),
                f"journal {self.path}:{line_number}.record_sha256",
            )
            if _record_digest(record) != record_hash:
                raise CampaignError(
                    f"journal {self.path}:{line_number} record hash drift"
                )
            if record.get("schema_version") != 1:
                raise CampaignError(
                    f"journal {self.path}:{line_number} has incompatible schema"
                )
            if record.get("lock_sha256") != self.lock_sha256:
                raise CampaignError(
                    f"journal {self.path}:{line_number} belongs to another lock"
                )
            record_type = record.get("record_type")
            if record_type == "invocation":
                require_exact_keys(record, INVOCATION_RECORD_KEYS, "journal invocation")
                invocation = require_int(
                    record["invocation"], "journal invocation index", minimum=0
                )
                if invocation in seen_invocations or invocation != len(self.invocations):
                    raise CampaignError("journal has duplicate or non-contiguous invocation")
                require_string(record["started_at"], "journal invocation started_at")
                require_int(record["pid"], "journal invocation pid", minimum=1)
                require_string(record["host"], "journal invocation host")
                if type(record["enforcement"]) is not dict:
                    raise CampaignError("journal invocation enforcement must be an object")
                seen_invocations.add(invocation)
                self.invocations.append(record)
            elif record_type == "run":
                if len(self.runs) >= len(self.jobs):
                    raise CampaignError("journal contains more runs than the lock schedule")
                job = self.jobs[len(self.runs)]
                if record.get("sequence") != job.sequence:
                    raise CampaignError("journal runs are not a contiguous schedule prefix")
                validate_run_record(record, job, seen_invocations)
                seen_run_keys.add(key_bytes)
                self.runs.append(record)
            else:
                raise CampaignError(
                    f"journal {self.path}:{line_number} has unknown record_type"
                )
            self.records.append(record)
            last_hash = record_hash
        self.last_hash = last_hash

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        assert self.fd is not None
        complete = dict(record)
        complete["previous_record_sha256"] = self.last_hash
        complete["record_sha256"] = _record_digest(complete)
        encoded = canonical_bytes(complete)
        offset = 0
        while offset < len(encoded):
            written = os.write(self.fd, encoded[offset:])
            if written <= 0:
                raise CampaignError(f"short append to journal {self.path}")
            offset += written
        os.fsync(self.fd)
        self.records.append(complete)
        self.last_hash = complete["record_sha256"]
        if complete["record_type"] == "invocation":
            self.invocations.append(complete)
        else:
            self.runs.append(complete)
        return complete


def atomic_write_immutable(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        try:
            existing = path.read_bytes()
        except OSError as error:
            raise CampaignError(f"cannot read existing final output {path}: {error}") from error
        if existing != content:
            raise CampaignError(f"existing final output drift: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise CampaignError(f"short write to temporary output {temporary}")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def raw_output_bytes(runs: list[dict[str, Any]]) -> bytes:
    return b"".join(canonical_bytes(record) for record in runs)


def build_summary(
    campaign: LockedCampaign,
    journal: Journal,
    raw_sha256: str,
    journal_sha256: str,
) -> dict[str, Any]:
    result_counts: dict[str, int] = {}
    termination_counts: dict[str, int] = {}
    for record in journal.runs:
        token = record["result_token"] or record["result_token_status"]
        result_counts[token] = result_counts.get(token, 0) + 1
        cause = record["termination_cause"]
        termination_counts[cause] = termination_counts.get(cause, 0) + 1
    return {
        "schema_version": 1,
        "status": "complete",
        "campaign_id": campaign.payload["campaign_id"],
        "lock_path": str(campaign.lock_path),
        "lock_sha256": campaign.payload["lock_sha256"],
        "promotion_eligible": campaign.payload["promotion_eligible"],
        "shard": campaign.payload.get("shard"),
        "continuation": campaign.payload.get("continuation"),
        "selected_runs": (
            len(campaign.payload["run_selection"])
            if "run_selection" in campaign.payload
            else None
        ),
        "repository_commit": campaign.payload["repository"]["commit"],
        "instances": len(campaign.payload["corpus"]["instances"]),
        "solvers": [solver["id"] for solver in campaign.payload["solvers"]],
        "budgets_s": campaign.payload["budgets_s"],
        "order": campaign.payload["execution"]["order"],
        "expected_runs": len(campaign.jobs),
        "completed_runs": len(journal.runs),
        "started_at": (
            journal.invocations[0]["started_at"] if journal.invocations else None
        ),
        "completed_at": journal.runs[-1]["finished_at"] if journal.runs else None,
        "journal": str(campaign.journal_path),
        "journal_sha256": journal_sha256,
        "journal_record_chain_head": journal.last_hash,
        "raw": str(campaign.raw_path),
        "raw_sha256": raw_sha256,
        "result_counts": dict(sorted(result_counts.items())),
        "termination_counts": dict(sorted(termination_counts.items())),
        "invocations": journal.invocations,
        "cgroup_or_benchexec_equivalent": False,
    }


def _ensure_output_paths(campaign: LockedCampaign) -> None:
    campaign.output_directory.mkdir(parents=True, exist_ok=True)
    for path in (campaign.journal_path, campaign.raw_path, campaign.summary_path):
        path.parent.mkdir(parents=True, exist_ok=True)


def run_campaign(lock_path: Path) -> dict[str, Any]:
    campaign = load_and_validate_lock(lock_path)
    snapshots = verify_frozen_artifacts(campaign)
    capabilities = enforcement_capabilities(campaign)
    _ensure_output_paths(campaign)
    lock_sha256 = campaign.payload["lock_sha256"]
    memory_bytes = campaign.payload["execution"]["memory_bytes"]
    grace_s = float(campaign.payload["execution"]["timeout_grace_s"])
    enforce_affinity = capabilities["cpu_affinity"]["enforced"]
    enforce_address_space = capabilities["address_space_limit"]["enforced"]

    with Journal(campaign.journal_path, lock_sha256, campaign.jobs) as journal:
        if len(journal.runs) < len(campaign.jobs):
            if campaign.raw_path.exists() or campaign.summary_path.exists():
                raise CampaignError(
                    "final output exists but the immutable journal is incomplete"
                )
            invocation_index = len(journal.invocations)
            journal.append(
                {
                    "record_type": "invocation",
                    "schema_version": 1,
                    "lock_sha256": lock_sha256,
                    "invocation": invocation_index,
                    "started_at": utc_now(),
                    "pid": os.getpid(),
                    "host": platform.node(),
                    "enforcement": capabilities,
                }
            )
            for job in campaign.jobs[len(journal.runs) :]:
                assert_unchanged(snapshots[campaign.lock_path])
                assert_unchanged(snapshots[campaign.instance_paths[job.instance_index]])
                assert_unchanged(snapshots[campaign.solver_paths[job.solver_index]])
                record = run_job(
                    job,
                    invocation_index,
                    lock_sha256,
                    campaign.output_directory,
                    campaign.payload["repository"]["commit"],
                    memory_bytes,
                    grace_s,
                    enforce_affinity,
                    enforce_address_space,
                )
                journal.append(record)
                print(
                    f"[{job.sequence + 1}/{len(campaign.jobs)}] "
                    f"{job.instance['relative_path']} {job.solver['id']} "
                    f"budget={job.budget_s} result="
                    f"{record['result_token'] or record['termination_cause']}",
                    flush=True,
                )

        if len(journal.runs) != len(campaign.jobs):
            raise CampaignError("journal did not reach the complete schedule")
        assert_all_unchanged(snapshots)
        raw_bytes = raw_output_bytes(journal.runs)
        raw_hash = sha256_bytes(raw_bytes)
        atomic_write_immutable(campaign.raw_path, raw_bytes)
        journal_hash = sha256_file(campaign.journal_path)
        summary = build_summary(campaign, journal, raw_hash, journal_hash)
        atomic_write_immutable(campaign.summary_path, canonical_bytes(summary))
        return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path, help="immutable campaign lock JSON")
    args = parser.parse_args(argv)
    try:
        summary = run_campaign(args.lock)
    except CampaignError as error:
        print(f"campaign failed: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("campaign interrupted; resume from the immutable journal", file=sys.stderr)
        return 130
    print(
        f"campaign complete: runs={summary['completed_runs']} "
        f"raw={summary['raw']}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
