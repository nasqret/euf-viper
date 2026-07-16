#!/usr/bin/env python3
"""Certify every correct euf-viper result in a validated locked campaign.

The supplied lock/raw pair is accepted only through the strict validator in
``scripts/bench/analyze_campaign.py``.  This tool then freezes deterministic
per-instance work identities, partitions them by modulo shard, runs each
certificate producer and checker in a fresh process group, and records every
attempt in an append-only, hash-chained JSONL journal.

Only a decisive result matching both the locked expectation and the
independent checker output is verified.  In particular, unknown, unsupported,
timeouts, malformed output, and checker abstention are failures.

For evidence-enabled locks, the timed production SAT model is validated first.
The later canonical ``certify`` invocation remains separate source-level
evidence and is never represented as a proof of the timed backend execution.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Mapping, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from strict_artifacts import (
    StrictArtifactError,
    assert_descriptor_path_nofollow,
    atomic_write_nofollow,
    canonical_nofollow_path,
    ensure_directory_nofollow,
    ensure_parent_directory_nofollow,
    open_verified_sealed_memfd,
    fsync_parent_nofollow,
    open_append_nofollow,
    read_regular_nofollow as strict_read_regular_nofollow,
)


ROOT = Path(__file__).resolve().parents[2]
ANALYZER_PATH = ROOT / "scripts" / "bench" / "analyze_campaign.py"
DEFAULT_CHECKER = ROOT / "scripts" / "cert" / "check_certificate.py"
INDEPENDENT_PARSER_PATH = ROOT / "scripts" / "cert" / "independent_qfuf.py"
PRODUCTION_CHECKER_PATH = ROOT / "scripts" / "cert" / "check_production_evidence.py"

SCHEMA_VERSION = 1
DECISIVE_RESULTS = {"sat", "unsat"}
ABSTENTIONS = {"unknown", "unsupported"}
HEX_DIGITS = frozenset("0123456789abcdef")
MAX_EXCERPT_BYTES = 2_000
MAX_JSON_OUTPUT_BYTES = 1024 * 1024
LINUX_PROC_FD = re.compile(r"/proc/self/fd/(?:[3-9]|[1-9][0-9]+)\Z")
CHECKER_BOOTSTRAP = """\
import importlib.machinery
import importlib.util
import runpy
import sys
checker, dependency, *arguments = sys.argv[1:]
loader = importlib.machinery.SourceFileLoader("independent_qfuf", dependency)
spec = importlib.util.spec_from_loader(loader.name, loader)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load descriptor-bound independent checker dependency")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
sys.argv = [checker, *arguments]
runpy.run_path(checker, run_name="__main__")
"""

WORK_KEYS = {
    "record_type",
    "schema_version",
    "parent_lock_sha256",
    "parent_lock_file_sha256",
    "parent_raw_sha256",
    "campaign_id",
    "global_index",
    "instance_id",
    "relative_path",
    "source_path",
    "source_sha256",
    "family",
    "expected_result",
    "solver_id",
    "solver_version",
    "solver_sha256",
    "decisive_budgets_s",
    "work_sha256",
}
PRODUCTION_EVIDENCE_BINDING_KEYS = {
    "path",
    "sha256",
    "bytes",
    "schema",
    "source_sha256",
    "solver_revision",
    "solver_executable_sha256",
    "solver_configuration",
    "solver_config_sha256",
    "solver_runtime_config_sha256",
    "solver_build_sha256",
    "sealed_build_receipt_sha256",
    "run_nonce",
    "status",
    "backend_status",
}
PRODUCTION_EVIDENCE_VALIDATION_KEYS = {
    "schema",
    "status",
    "backend_status",
    "run_nonce",
    "evidence_sha256",
    "evidence_bytes",
    "source_sha256",
    "solver_revision",
    "solver_executable_sha256",
    "solver_config_sha256",
    "solver_build_sha256",
    "sealed_build_receipt_sha256",
    "terms",
    "atoms",
    "assignment_variables",
    "initial_backend_clauses",
    "backend_clauses",
}
PROCESS_KEYS = {
    "status",
    "exit_code",
    "timed_out",
    "spawn_error",
    "descriptor_binding",
    "wall_time_s",
    "stdout_path",
    "stdout_sha256",
    "stdout_bytes",
    "stdout_excerpt",
    "stderr_path",
    "stderr_sha256",
    "stderr_bytes",
    "stderr_excerpt",
}
ARTIFACT_KEYS = {
    "manifest_path",
    "manifest_sha256",
    "dimacs_path",
    "dimacs_sha256",
    "proof_path",
    "proof_sha256",
}
ATTEMPT_KEYS = {
    "record_type",
    "schema_version",
    "parent_lock_sha256",
    "plan_sha256",
    "sequence",
    "work_index",
    "work_sha256",
    "attempt",
    "instance_id",
    "relative_path",
    "source_path",
    "source_sha256",
    "solver_sha256",
    "expected_result",
    "started_at",
    "finished_at",
    "certify_command",
    "checker_command",
    "certify_process",
    "checker_process",
    "artifacts",
    "verified",
    "failure_kind",
    "failure_message",
    "previous_record_sha256",
    "record_sha256",
}
FAILURE_KINDS = {
    "certify_timeout",
    "certify_spawn_error",
    "certify_signal",
    "certify_exit",
    "certify_abstention",
    "certify_output",
    "result_mismatch",
    "manifest_missing",
    "manifest_invalid",
    "manifest_mismatch",
    "artifact_mismatch",
    "checker_timeout",
    "checker_spawn_error",
    "checker_signal",
    "checker_exit",
    "checker_output",
    "checker_mismatch",
    "input_drift",
    "interrupted",
}


class ShadowError(ValueError):
    """Raised when evidence, execution, or resume state is not trustworthy."""


class ShadowInterrupted(Exception):
    """Raised after an interrupted attempt has been durably journaled."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _require_hash(value: object, context: str) -> str:
    if not _is_sha256(value):
        raise ShadowError(f"{context} must be a lowercase SHA-256")
    assert isinstance(value, str)
    return value


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        _, content = strict_read_regular_nofollow(path, f"hash input {path}")
    except StrictArtifactError as error:
        raise ShadowError(f"cannot hash {path}: {error}") from error
    return sha256_bytes(content)


def _read_regular_nofollow(path: Path, context: str) -> bytes:
    try:
        _, content = strict_read_regular_nofollow(path, context)
        return content
    except StrictArtifactError as error:
        raise ShadowError(str(error)) from error


def _expected_runtime_config(environment: Mapping[str, str]) -> dict[str, str]:
    controls = {
        "EUF_VIPER_RUN_NONCE",
        "EUF_VIPER_TRUSTED_EXECUTABLE_SHA256",
        "EUF_VIPER_SEALED_BUILD_RECEIPT",
    }
    config = {
        key: value
        for key, value in environment.items()
        if key.startswith("EUF_VIPER_") and key not in controls
    }
    for name, default, resolved in (
        ("EUF_VIPER_DIRECT_ROOT_CNF", "1", "resolved.direct_root_cnf"),
        ("EUF_VIPER_DIRECT_NEGATED_ROOT", "0", "resolved.direct_negated_root"),
    ):
        setting = environment.get(name, default)
        if setting not in {"0", "1"}:
            raise ShadowError(f"locked {name} is invalid")
        config[resolved] = setting
    config.update(
        {
            "resolved.production_evidence_contract": "deterministic-cnf-transcript-v1",
            "resolved.production_evidence_mode": "cnf-assignment-transcript",
            "resolved.eq_abstraction": "off",
            "resolved.finite_domain": "off",
            "resolved.full_ackermann": "off",
            "resolved.chordal_transitivity": "off",
            "resolved.refinement_mode": "model-cuts",
        }
    )
    return dict(sorted(config.items()))


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in HEX_DIGITS for character in value)
    )


def _record_digest(record: Mapping[str, Any]) -> str:
    unhashed = dict(record)
    unhashed.pop("record_sha256", None)
    return sha256_bytes(canonical_bytes(unhashed))


def _work_digest(work: Mapping[str, Any]) -> str:
    unhashed = dict(work)
    unhashed["work_sha256"] = ""
    return sha256_bytes(canonical_bytes(unhashed))


def _strict_json(text: str, context: str) -> Any:
    def reject_constant(value: str) -> Any:
        raise ValueError(f"non-finite JSON number {value!r}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(
            text,
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ShadowError(f"{context}: invalid JSON: {error}") from error


def _require_exact_keys(
    value: object, expected: set[str], context: str
) -> dict[str, Any]:
    if type(value) is not dict:
        raise ShadowError(f"{context}: must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ShadowError(
            f"{context}: incorrect fields; missing={missing!r}, extra={extra!r}"
        )
    return value


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ShadowError(f"cannot import campaign dependency {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    return module


def _load_analyzer() -> ModuleType:
    return _load_module("shadow_campaign_analyze_campaign", ANALYZER_PATH)


def load_validated_campaign(lock_path: Path, raw_path: Path) -> dict[str, Any]:
    """Load one lock/raw pair exclusively through the campaign strict validator."""

    analyzer = _load_analyzer()
    try:
        campaign = analyzer.load_locked_campaign(lock_path, raw_path)
    except analyzer.CampaignInputError as error:
        details = "; ".join(error.errors)
        raise ShadowError(f"locked campaign validation failed: {details}") from error
    if type(campaign) is not dict:
        raise ShadowError("strict campaign validator returned an invalid payload")
    return campaign


def _resolve_source(
    instance: Mapping[str, Any], lock_path: Path, corpus_root: Path | None
) -> Path:
    if corpus_root is not None:
        relative = PurePosixPath(instance["relative_path"])
        candidate = corpus_root.joinpath(*relative.parts)
    else:
        candidate = Path(instance["path"]).expanduser()
        if not candidate.is_absolute():
            candidate = lock_path.parent / candidate
    resolved = canonical_nofollow_path(candidate)
    try:
        resolved, source_bytes = strict_read_regular_nofollow(
            resolved, f"locked source {instance['relative_path']!r}"
        )
    except StrictArtifactError as error:
        raise ShadowError(str(error)) from error
    actual_hash = sha256_bytes(source_bytes)
    if actual_hash != instance["sha256"]:
        raise ShadowError(
            f"source SHA-256 mismatch for {instance['relative_path']!r}: "
            f"locked {instance['sha256']}, actual {actual_hash}"
        )
    locked_bytes = instance.get("bytes")
    if type(locked_bytes) is not int or locked_bytes < 0:
        raise ShadowError(
            f"locked source byte count is invalid for {instance['relative_path']!r}"
        )
    actual_bytes = len(source_bytes)
    if actual_bytes != locked_bytes:
        raise ShadowError(
            f"source byte-count mismatch for {instance['relative_path']!r}: "
            f"locked {locked_bytes}, actual {actual_bytes}"
        )
    return resolved


def _candidate_solver(lock: Mapping[str, Any]) -> dict[str, Any]:
    matches = [solver for solver in lock["solvers"] if solver["id"] == "euf-viper"]
    if len(matches) != 1:
        raise ShadowError(
            "locked campaign must contain exactly one solver with id 'euf-viper'"
        )
    return matches[0]


def derive_work_records(
    campaign: Mapping[str, Any],
    lock_path: Path,
    *,
    corpus_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Select decisive candidate rows and reject any wrong candidate claim."""

    lock = campaign["lock"]
    solver = _candidate_solver(lock)
    locked_environment = dict(lock["execution"]["environment"])
    locked_environment.update(solver["environment"])
    locked_runtime_config = _expected_runtime_config(locked_environment)
    observations = campaign["observations"]
    candidate_budgets: dict[str, list[float]] = collections.defaultdict(list)
    candidate_evidence: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    production_checker = None
    if "evidence" in solver:
        production_checker = _load_module(
            "shadow_campaign_check_production_evidence", PRODUCTION_CHECKER_PATH
        )
    for key, observation in observations.items():
        relative_path, budget_s, solver_id = key
        if solver_id != "euf-viper":
            continue
        if observation["binary_sha256"] != solver["sha256"]:
            raise ShadowError(
                f"validated observation solver hash drift for {relative_path!r}"
            )
        if observation["result"] in DECISIVE_RESULTS:
            if observation["result"] != observation["expected_status"]:
                raise ShadowError(
                    "wrong decisive euf-viper observation: "
                    f"{relative_path!r} at budget {budget_s} claimed "
                    f"{observation['result']!r}, expected "
                    f"{observation['expected_status']!r}"
                )
            candidate_budgets[relative_path].append(float(budget_s))
            if "evidence" in solver:
                bindings = observation.get("production_evidence")
                if type(bindings) is not list or len(bindings) != observation["repetitions"]:
                    raise ShadowError(
                        f"production evidence count mismatch for {relative_path!r} "
                        f"at budget {budget_s}"
                    )
                for repetition, binding in enumerate(bindings):
                    if type(binding) is not dict:
                        raise ShadowError(
                            f"missing decisive production evidence for {relative_path!r}"
                        )
                    candidate_evidence[relative_path].append(
                        {
                            "budget_s": float(budget_s),
                            "repetition": repetition,
                            "binding": binding,
                        }
                    )
    selected: list[tuple[Mapping[str, Any], list[float], Path]] = []

    for instance in lock["corpus"]["instances"]:
        decisive_budgets = candidate_budgets.get(instance["relative_path"], [])
        if decisive_budgets:
            if instance["status"] not in DECISIVE_RESULTS:
                raise ShadowError(
                    "locked instance has non-decisive status: "
                    f"{instance['relative_path']!r}"
                )
            source = _resolve_source(instance, lock_path, corpus_root)
            selected.append(
                (instance, sorted(set(decisive_budgets)), source)
            )

    selected.sort(key=lambda item: (item[0]["relative_path"], str(item[0]["id"])))
    works: list[dict[str, Any]] = []
    for global_index, (instance, budgets, source) in enumerate(selected):
        validated_production_evidence: list[dict[str, Any]] = []
        if production_checker is not None:
            output_directory = Path(lock["output"]["directory"])
            for production in sorted(
                candidate_evidence[instance["relative_path"]],
                key=lambda value: (value["budget_s"], value["repetition"]),
            ):
                binding = production["binding"]
                evidence_path = output_directory / binding["path"]
                try:
                    validation = production_checker.validate_production_evidence(
                        evidence_path,
                        source,
                        expected_source_sha256=instance["sha256"],
                        expected_revision=lock["repository"]["commit"],
                        expected_status=instance["status"],
                        expected_executable_sha256=solver["sha256"],
                        expected_runtime_config=locked_runtime_config,
                        expected_evidence_sha256=binding["sha256"],
                        expected_run_nonce=binding["run_nonce"],
                    )
                except (OSError, production_checker.ProductionEvidenceError) as error:
                    raise ShadowError(
                        f"production evidence rejected for {instance['relative_path']!r}: {error}"
                    ) from error
                if (
                    validation["solver_config_sha256"]
                    != binding["solver_runtime_config_sha256"]
                ):
                    raise ShadowError(
                        "production evidence runtime config drift for "
                        f"{instance['relative_path']!r}"
                    )
                if (
                    validation["evidence_sha256"] != binding["sha256"]
                    or validation["evidence_bytes"] != binding["bytes"]
                    or validation["solver_executable_sha256"]
                    != binding["solver_executable_sha256"]
                    or validation["solver_build_sha256"]
                    != binding["solver_build_sha256"]
                    or validation["sealed_build_receipt_sha256"]
                    != binding["sealed_build_receipt_sha256"]
                ):
                    raise ShadowError(
                        "production evidence journal binding drift for "
                        f"{instance['relative_path']!r}"
                    )
                validated_production_evidence.append(
                    {
                        "budget_s": production["budget_s"],
                        "repetition": production["repetition"],
                        "binding": binding,
                        "artifact_path": str(evidence_path),
                        "validation": validation,
                    }
                )
        work: dict[str, Any] = {
            "record_type": "work",
            "schema_version": SCHEMA_VERSION,
            "parent_lock_sha256": lock["lock_sha256"],
            "parent_lock_file_sha256": campaign["lock_file_sha256"],
            "parent_raw_sha256": campaign["raw_sha256"],
            "campaign_id": lock["campaign_id"],
            "global_index": global_index,
            "instance_id": instance["id"],
            "relative_path": instance["relative_path"],
            "source_path": str(source),
            "source_sha256": instance["sha256"],
            "family": instance["family"],
            "expected_result": instance["status"],
            "solver_id": solver["id"],
            "solver_version": solver["version"],
            "solver_sha256": solver["sha256"],
            "decisive_budgets_s": budgets,
            "work_sha256": "",
        }
        if production_checker is not None:
            work["production_evidence"] = validated_production_evidence
        work["work_sha256"] = _work_digest(work)
        works.append(work)
    return works


def validate_independent_parser_workset(
    works: Sequence[Mapping[str, Any]],
    parser_path: Path = INDEPENDENT_PARSER_PATH,
) -> dict[str, Any]:
    """Parse every selected source before a certificate array is released."""

    try:
        parser_path = parser_path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ShadowError(f"cannot resolve independent parser: {error}") from error
    if not parser_path.is_file():
        raise ShadowError(f"independent parser is not a file: {parser_path}")
    parser = _load_module("certificate_shadow_independent_qfuf_canary", parser_path)
    parser_hash = sha256_file(parser_path)
    records: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for index, work in enumerate(works):
        relative_path = work.get("relative_path")
        source_path = work.get("source_path")
        expected_hash = work.get("source_sha256")
        if type(relative_path) is not str or not relative_path:
            raise ShadowError(f"parser canary work {index} has an invalid relative path")
        if relative_path in seen_paths:
            raise ShadowError(f"parser canary workset repeats {relative_path!r}")
        seen_paths.add(relative_path)
        if type(source_path) is not str or not source_path:
            raise ShadowError(
                f"parser canary work {relative_path!r} has no source path"
            )
        if type(expected_hash) is not str or not _is_sha256(expected_hash):
            raise ShadowError(
                f"parser canary work {relative_path!r} has an invalid source hash"
            )
        source = canonical_nofollow_path(Path(source_path))
        try:
            source, source_bytes = strict_read_regular_nofollow(
                source, f"parser canary source {relative_path!r}"
            )
        except StrictArtifactError as error:
            raise ShadowError(str(error)) from error
        if sha256_bytes(source_bytes) != expected_hash:
            raise ShadowError(f"parser canary source SHA-256 mismatch for {relative_path!r}")
        try:
            source_text = source_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ShadowError(
                f"independent parser canary rejected {relative_path!r}: "
                f"source is not UTF-8: {error}"
            ) from error
        try:
            problem = parser.parse_and_encode(source_text)
        except parser.IndependentQfufError as error:
            raise ShadowError(
                f"independent parser canary rejected {relative_path!r}: {error}"
            ) from error
        records.append(
            {
                "relative_path": relative_path,
                "source_sha256": expected_hash,
                "terms": len(problem.terms),
                "atoms": len(problem.atoms),
                "base_clauses": len(problem.clauses),
                "bool_data_terms": len(problem.bool_data_terms),
            }
        )
    records.sort(key=lambda record: record["relative_path"])
    return {
        "schema_version": 1,
        "status": "validated",
        "parser": {"path": str(parser_path), "sha256": parser_hash},
        "selected_instances": len(records),
        "workset_sha256": sha256_bytes(canonical_bytes(records)),
        "totals": {
            "terms": sum(record["terms"] for record in records),
            "atoms": sum(record["atoms"] for record in records),
            "base_clauses": sum(record["base_clauses"] for record in records),
            "bool_data_terms": sum(record["bool_data_terms"] for record in records),
        },
    }


def validate_work_record(work: object, context: str = "work record") -> dict[str, Any]:
    expected_keys = WORK_KEYS | (
        {"production_evidence"}
        if type(work) is dict and "production_evidence" in work
        else set()
    )
    value = _require_exact_keys(work, expected_keys, context)
    if value["record_type"] != "work" or value["schema_version"] != SCHEMA_VERSION:
        raise ShadowError(f"{context}: invalid record type or schema")
    for field in (
        "parent_lock_sha256",
        "parent_lock_file_sha256",
        "parent_raw_sha256",
        "source_sha256",
        "solver_sha256",
        "work_sha256",
    ):
        if not _is_sha256(value[field]):
            raise ShadowError(f"{context}: {field} is not a canonical SHA-256")
    if value["work_sha256"] != _work_digest(value):
        raise ShadowError(f"{context}: work SHA-256 mismatch")
    if type(value["global_index"]) is not int or value["global_index"] < 0:
        raise ShadowError(f"{context}: global_index must be non-negative")
    if value["expected_result"] not in DECISIVE_RESULTS:
        raise ShadowError(f"{context}: expected_result must be sat or unsat")
    budgets = value["decisive_budgets_s"]
    if type(budgets) is not list or not budgets:
        raise ShadowError(f"{context}: decisive_budgets_s must be non-empty")
    if any(
        type(item) not in {int, float} or not math.isfinite(item) or item <= 0
        for item in budgets
    ):
        raise ShadowError(f"{context}: invalid decisive budget")
    if budgets != sorted(set(float(item) for item in budgets)):
        raise ShadowError(f"{context}: decisive budgets are not canonical")
    if "production_evidence" in value:
        production = value["production_evidence"]
        if type(production) is not list or not production:
            raise ShadowError(f"{context}: production_evidence must be non-empty")
        if value["expected_result"] != "sat":
            raise ShadowError(f"{context}: production evidence currently certifies SAT only")
        seen_runs: set[tuple[float, int]] = set()
        covered_budgets: set[float] = set()
        for index, record in enumerate(production):
            if type(record) is not dict or set(record) != {
                "budget_s",
                "repetition",
                "binding",
                "artifact_path",
                "validation",
            }:
                raise ShadowError(
                    f"{context}: production_evidence[{index}] has invalid structure"
                )
            if record["budget_s"] not in budgets:
                raise ShadowError(
                    f"{context}: production evidence references an unknown budget"
                )
            if type(record["repetition"]) is not int or record["repetition"] < 0:
                raise ShadowError(f"{context}: production evidence repetition is invalid")
            run_key = (float(record["budget_s"]), record["repetition"])
            if run_key in seen_runs:
                raise ShadowError(f"{context}: duplicate production evidence run")
            seen_runs.add(run_key)
            covered_budgets.add(run_key[0])

            binding = _require_exact_keys(
                record["binding"],
                PRODUCTION_EVIDENCE_BINDING_KEYS,
                f"{context}.production_evidence[{index}].binding",
            )
            artifact_value = record["artifact_path"]
            if type(artifact_value) is not str or not Path(artifact_value).is_absolute():
                raise ShadowError(f"{context}: invalid production evidence artifact_path")
            path_value = binding["path"]
            if type(path_value) is not str or not path_value:
                raise ShadowError(f"{context}: invalid production evidence path")
            artifact_path = PurePosixPath(path_value)
            if artifact_path.is_absolute() or ".." in artifact_path.parts:
                raise ShadowError(f"{context}: invalid production evidence path")
            for field in (
                "sha256",
                "source_sha256",
                "solver_config_sha256",
                "solver_runtime_config_sha256",
                "solver_executable_sha256",
                "solver_build_sha256",
                "sealed_build_receipt_sha256",
                "run_nonce",
            ):
                if not _is_sha256(binding[field]):
                    raise ShadowError(f"{context}: invalid production evidence {field}")
            if type(binding["bytes"]) is not int or binding["bytes"] < 1:
                raise ShadowError(f"{context}: invalid production evidence byte count")
            if binding["schema"] != "euf-viper.production-evidence.v4":
                raise ShadowError(f"{context}: invalid production evidence schema")
            if binding["source_sha256"] != value["source_sha256"]:
                raise ShadowError(f"{context}: production evidence source hash mismatch")
            if (
                type(binding["solver_revision"]) is not str
                or not binding["solver_revision"]
                or type(binding["solver_configuration"]) is not str
                or not binding["solver_configuration"]
            ):
                raise ShadowError(f"{context}: invalid production solver identity")
            if binding["status"] != "sat" or binding["backend_status"] != "sat":
                raise ShadowError(f"{context}: production evidence is not decisive SAT")

            validation = _require_exact_keys(
                record["validation"],
                PRODUCTION_EVIDENCE_VALIDATION_KEYS,
                f"{context}.production_evidence[{index}].validation",
            )
            expected_validation = {
                "schema": binding["schema"],
                "status": binding["status"],
                "backend_status": binding["backend_status"],
                "run_nonce": binding["run_nonce"],
                "evidence_sha256": binding["sha256"],
                "evidence_bytes": binding["bytes"],
                "source_sha256": binding["source_sha256"],
                "solver_revision": binding["solver_revision"],
                "solver_executable_sha256": binding["solver_executable_sha256"],
                "solver_config_sha256": binding["solver_runtime_config_sha256"],
                "solver_build_sha256": binding["solver_build_sha256"],
                "sealed_build_receipt_sha256": binding[
                    "sealed_build_receipt_sha256"
                ],
            }
            for field, expected in expected_validation.items():
                if validation[field] != expected:
                    raise ShadowError(
                        f"{context}: production evidence validation {field} mismatch"
                    )
            for field in (
                "terms",
                "atoms",
                "assignment_variables",
                "initial_backend_clauses",
                "backend_clauses",
            ):
                if type(validation[field]) is not int or validation[field] < 0:
                    raise ShadowError(
                        f"{context}: invalid production evidence validation {field}"
                    )
        if covered_budgets != set(float(item) for item in budgets):
            raise ShadowError(f"{context}: production evidence does not cover every budget")
    return value


def rehash_production_evidence(works: Sequence[Mapping[str, Any]]) -> None:
    for work in works:
        for production in work.get("production_evidence", []):
            binding = production["binding"]
            artifact_path = Path(production["artifact_path"])
            content = _read_regular_nofollow(
                artifact_path,
                f"production evidence for {work['relative_path']!r}",
            )
            actual_hash = hashlib.sha256(content).hexdigest()
            if actual_hash != binding["sha256"] or len(content) != binding["bytes"]:
                raise ShadowError(
                    "production evidence no longer matches its campaign journal binding: "
                    f"{artifact_path}"
                )
            validation = production["validation"]
            if (
                validation["evidence_sha256"] != actual_hash
                or validation["evidence_bytes"] != len(content)
            ):
                raise ShadowError(
                    f"production evidence validation hash drift: {artifact_path}"
                )


def partition_work_records(
    works: Sequence[dict[str, Any]], shard_index: int, shard_count: int
) -> list[dict[str, Any]]:
    """Return the deterministic modulo partition for one shard."""

    if type(shard_count) is not int or shard_count < 1:
        raise ShadowError("shard count must be at least one")
    if type(shard_index) is not int or not 0 <= shard_index < shard_count:
        raise ShadowError("shard index must be in [0, shard count)")
    for position, work in enumerate(works):
        validate_work_record(work, f"work record {position}")
        if work["global_index"] != position:
            raise ShadowError("work records must have contiguous global indices")
    rehash_production_evidence(works)
    return [work for work in works if work["global_index"] % shard_count == shard_index]


def resolve_executable(value: str | Path, label: str) -> Path:
    raw = str(value)
    candidate = Path(raw).expanduser()
    contains_separator = os.sep in raw or (os.altsep is not None and os.altsep in raw)
    if contains_separator or candidate.exists():
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ShadowError(f"cannot resolve {label} {raw!r}: {error}") from error
    else:
        found = shutil.which(raw)
        if found is None:
            raise ShadowError(f"cannot find {label}: {raw}")
        resolved = Path(found).resolve()
    if not resolved.is_file():
        raise ShadowError(f"{label} is not a file: {resolved}")
    if not os.access(resolved, os.X_OK):
        raise ShadowError(f"{label} is not executable: {resolved}")
    return resolved


def _environment_hash(environment: Mapping[str, str]) -> str:
    return sha256_bytes(canonical_bytes(dict(sorted(environment.items()))))


def build_plan_record(
    campaign: Mapping[str, Any],
    works: Sequence[dict[str, Any]],
    shard_works: Sequence[dict[str, Any]],
    *,
    solver_path: Path,
    python_path: Path,
    checker_path: Path,
    independent_parser_path: Path,
    drat_trim_path: Path | None,
    corpus_root: Path | None,
    timeout_s: float,
    checker_timeout_s: float,
    timeout_grace_s: float,
    max_theory_rounds: int | None,
    shard_index: int,
    shard_count: int,
    certify_environment: Mapping[str, str],
    checker_environment: Mapping[str, str],
) -> dict[str, Any]:
    lock = campaign["lock"]
    solver = _candidate_solver(lock)
    plan: dict[str, Any] = {
        "record_type": "plan",
        "schema_version": SCHEMA_VERSION,
        "campaign_id": lock["campaign_id"],
        "parent_lock_sha256": lock["lock_sha256"],
        "parent_lock_file_sha256": campaign["lock_file_sha256"],
        "parent_raw_sha256": campaign["raw_sha256"],
        "solver": {
            "id": solver["id"],
            "path": str(solver_path),
            "sha256": solver["sha256"],
        },
        "python": {
            "path": str(python_path),
            "sha256": sha256_file(python_path),
        },
        "checker": {
            "path": str(checker_path),
            "sha256": sha256_file(checker_path),
        },
        "independent_parser": {
            "path": str(independent_parser_path),
            "sha256": sha256_file(independent_parser_path),
        },
        "drat_trim": (
            {
                "path": str(drat_trim_path),
                "sha256": sha256_file(drat_trim_path),
            }
            if drat_trim_path is not None
            else None
        ),
        "configuration": {
            "corpus_root": (
                str(canonical_nofollow_path(corpus_root))
                if corpus_root is not None
                else None
            ),
            "timeout_s": timeout_s,
            "checker_timeout_s": checker_timeout_s,
            "timeout_grace_s": timeout_grace_s,
            "max_theory_rounds": max_theory_rounds,
            "certify_environment_sha256": _environment_hash(certify_environment),
            "checker_environment_sha256": _environment_hash(checker_environment),
            "process_model": "cold_process_group_per_command",
        },
        "selection": {
            "selected_instances": len(works),
            "workset_sha256": sha256_bytes(
                canonical_bytes([work["work_sha256"] for work in works])
            ),
            "shard_index": shard_index,
            "shard_count": shard_count,
            "shard_instances": len(shard_works),
            "shard_workset_sha256": sha256_bytes(
                canonical_bytes([work["work_sha256"] for work in shard_works])
            ),
        },
        "previous_record_sha256": None,
    }
    plan["record_sha256"] = _record_digest(plan)
    return plan


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def _output_relative(path: Path, output_directory: Path) -> str:
    try:
        relative = path.relative_to(output_directory)
    except ValueError as error:
        raise ShadowError(f"artifact path escapes output directory: {path}") from error
    value = PurePosixPath(*relative.parts).as_posix()
    if not value or value == "." or ".." in PurePosixPath(value).parts:
        raise ShadowError(f"invalid artifact relative path: {value!r}")
    return value


def _artifact_absolute(relative: str, output_directory: Path) -> Path:
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or not relative or ".." in parsed.parts:
        raise ShadowError(f"unsafe journal artifact path {relative!r}")
    output_directory = canonical_nofollow_path(output_directory)
    candidate = canonical_nofollow_path(output_directory.joinpath(*parsed.parts))
    try:
        candidate.relative_to(output_directory)
    except ValueError as error:
        raise ShadowError(f"journal artifact escapes output directory: {relative!r}")
    return candidate


def _read_output(path: Path) -> bytes:
    try:
        _, content = strict_read_regular_nofollow(path, f"process output {path}")
        return content
    except StrictArtifactError as error:
        raise ShadowError(str(error)) from error


def _inspect_output(path: Path) -> tuple[str, int, str]:
    if path.is_symlink():
        raise ShadowError(f"process output cannot be a symlink: {path}")
    digest = hashlib.sha256()
    byte_count = 0
    prefix = bytearray()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
                byte_count += len(block)
                if len(prefix) < MAX_EXCERPT_BYTES:
                    prefix.extend(block[: MAX_EXCERPT_BYTES - len(prefix)])
    except OSError as error:
        raise ShadowError(f"cannot inspect process output {path}: {error}") from error
    excerpt = bytes(prefix).decode("utf-8", errors="replace").strip()
    if byte_count > MAX_EXCERPT_BYTES:
        excerpt += "..."
    return digest.hexdigest(), byte_count, excerpt


def _signal_group(pid: int, sent_signal: signal.Signals) -> None:
    try:
        os.killpg(pid, sent_signal)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise ShadowError(f"cannot signal process group {pid}: {error}") from error


def _terminate_process_group(process: subprocess.Popen[bytes], grace_s: float) -> None:
    _signal_group(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=grace_s)
    except subprocess.TimeoutExpired:
        _signal_group(process.pid, signal.SIGKILL)
        process.wait()
    finally:
        # The leader can exit while a descendant remains in the process group.
        _signal_group(process.pid, signal.SIGKILL)


def run_cold_process(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    timeout_s: float,
    grace_s: float,
    stdout_path: Path,
    stderr_path: Path,
    output_directory: Path,
    descriptor_hashes: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run one command in a fresh process group and durably capture its output."""

    descriptor_available = sys.platform.startswith("linux") and Path(
        "/proc/self/fd"
    ).is_dir()
    descriptor_required = bool(descriptor_hashes) or (
        os.environ.get("EUF_VIPER_DESCRIPTOR_EXECUTION") == "required"
    )
    if descriptor_required and not descriptor_available:
        raise ShadowError(
            "certificate execution requires Linux /proc/self/fd descriptor binding"
        )
    stdout_fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        stderr_fd = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except BaseException:
        os.close(stdout_fd)
        raise

    process: subprocess.Popen[bytes] | None = None
    status = "spawn_error"
    exit_code: int | None = None
    spawn_error: str | None = None
    timed_out = False
    started = time.monotonic()
    execution_command = list(command)
    bound_descriptors: list[int] = []
    descriptor_records: list[dict[str, str]] = []
    if descriptor_available and descriptor_hashes:
        replacements: dict[str, str] = {}
        try:
            for raw_path, expected_hash in sorted(descriptor_hashes.items()):
                path = Path(raw_path)
                try:
                    descriptor = open_verified_sealed_memfd(
                        path, expected_hash, f"bound execution input {path}"
                    )
                except StrictArtifactError as error:
                    raise ShadowError(str(error)) from error
                bound_descriptors.append(descriptor)
                execution_path = f"/proc/self/fd/{descriptor}"
                replacements[raw_path] = execution_path
                descriptor_records.append(
                    {
                        "execution_path": execution_path,
                        "path": raw_path,
                        "sha256": expected_hash,
                    }
                )
            execution_command = [replacements.get(argument, argument) for argument in command]
            if not command or execution_command[0] == command[0]:
                raise ShadowError("descriptor execution did not bind the command executable")
            for raw_path in descriptor_hashes:
                if raw_path not in command:
                    raise ShadowError(
                        f"descriptor-bound path is absent from the command: {raw_path}"
                    )
        except BaseException:
            for descriptor in bound_descriptors:
                os.close(descriptor)
            raise
    descriptor_binding = {
        "mechanism": "linux_procfd" if descriptor_available else "platform_pathname",
        "files": descriptor_records,
    }
    try:
        try:
            process = subprocess.Popen(
                execution_command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_fd,
                stderr=stderr_fd,
                env=dict(environment),
                close_fds=True,
                pass_fds=tuple(bound_descriptors),
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError) as error:
            spawn_error = f"{type(error).__name__}: {error}"
        finally:
            for descriptor in bound_descriptors:
                os.close(descriptor)
            os.close(stdout_fd)
            os.close(stderr_fd)

        if process is not None:
            try:
                exit_code = process.wait(timeout=timeout_s)
                status = "signal" if exit_code < 0 else "exit"
                _signal_group(process.pid, signal.SIGKILL)
            except subprocess.TimeoutExpired:
                timed_out = True
                status = "timeout"
                _terminate_process_group(process, grace_s)
                exit_code = process.returncode
            except KeyboardInterrupt:
                status = "interrupted"
                _terminate_process_group(process, grace_s)
                exit_code = process.returncode
    finally:
        if process is None:
            for descriptor in (stdout_fd, stderr_fd):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    wall_time_s = time.monotonic() - started
    stdout_hash, stdout_bytes, stdout_excerpt = _inspect_output(stdout_path)
    stderr_hash, stderr_bytes, stderr_excerpt = _inspect_output(stderr_path)
    return {
        "status": status,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "spawn_error": spawn_error,
        "descriptor_binding": descriptor_binding,
        "wall_time_s": wall_time_s,
        "stdout_path": _output_relative(stdout_path, output_directory),
        "stdout_sha256": stdout_hash,
        "stdout_bytes": stdout_bytes,
        "stdout_excerpt": stdout_excerpt,
        "stderr_path": _output_relative(stderr_path, output_directory),
        "stderr_sha256": stderr_hash,
        "stderr_bytes": stderr_bytes,
        "stderr_excerpt": stderr_excerpt,
    }


def _certify_result(stdout_path: Path) -> tuple[str | None, str]:
    data = _read_output(stdout_path)
    if len(data) > 128:
        return None, "malformed"
    try:
        tokens = data.decode("ascii").split()
    except UnicodeDecodeError:
        return None, "malformed"
    if len(tokens) != 1:
        return None, "missing" if not tokens else "malformed"
    if tokens[0] in DECISIVE_RESULTS:
        return tokens[0], "decisive"
    if tokens[0] in ABSTENTIONS:
        return tokens[0], "abstention"
    return None, "malformed"


def _known_artifact_paths(prefix: Path, output_directory: Path) -> dict[str, str]:
    return {
        "manifest_path": _output_relative(Path(f"{prefix}.euf.json"), output_directory),
        "dimacs_path": _output_relative(Path(f"{prefix}.cnf"), output_directory),
        "proof_path": _output_relative(Path(f"{prefix}.drat"), output_directory),
    }


def _collect_artifacts(prefix: Path, output_directory: Path) -> dict[str, Any]:
    paths = _known_artifact_paths(prefix, output_directory)
    result: dict[str, Any] = {}
    for label in ("manifest", "dimacs", "proof"):
        relative = paths[f"{label}_path"]
        absolute = _artifact_absolute(relative, output_directory)
        result[f"{label}_path"] = relative
        if not os.path.lexists(absolute):
            result[f"{label}_sha256"] = None
            continue
        result[f"{label}_sha256"] = sha256_file(absolute)
    return result


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        _, manifest_bytes = strict_read_regular_nofollow(
            path, f"certificate manifest {path}"
        )
        raw = manifest_bytes.decode("utf-8")
    except (StrictArtifactError, UnicodeError) as error:
        raise ShadowError(f"cannot read certificate manifest {path}: {error}") from error
    value = _strict_json(raw, f"certificate manifest {path}")
    if type(value) is not dict:
        raise ShadowError(f"certificate manifest {path}: root must be an object")
    return value


def _resolve_declared_artifact(value: object, label: str) -> Path:
    if type(value) is not str or not value:
        raise ShadowError(f"certificate manifest has invalid {label} path")
    return canonical_nofollow_path(Path(value))


def _validate_descriptor_binding(value: object, context: str) -> dict[str, Any]:
    binding = _require_exact_keys(value, {"files", "mechanism"}, context)
    mechanism = binding["mechanism"]
    if mechanism not in {"linux_procfd", "platform_pathname"}:
        raise ShadowError(f"{context}: invalid descriptor mechanism")
    files = binding["files"]
    if type(files) is not list:
        raise ShadowError(f"{context}: invalid descriptor file bindings")

    seen_paths: set[str] = set()
    seen_execution_paths: set[str] = set()
    expected_keys = (
        {"execution_path", "path", "sha256"}
        if mechanism == "linux_procfd"
        else {"path", "sha256"}
    )
    for index, raw_item in enumerate(files):
        item = _require_exact_keys(
            raw_item, expected_keys, f"{context} file {index}"
        )
        path = item["path"]
        if type(path) is not str or not path:
            raise ShadowError(f"{context}: descriptor path must be a nonempty string")
        if path in seen_paths:
            raise ShadowError(f"{context}: duplicate descriptor path {path!r}")
        seen_paths.add(path)
        _require_hash(item["sha256"], f"{context} file {index} SHA-256")
        if mechanism == "linux_procfd":
            execution_path = item["execution_path"]
            if (
                type(execution_path) is not str
                or LINUX_PROC_FD.fullmatch(execution_path) is None
            ):
                raise ShadowError(
                    f"{context}: invalid Linux procfd execution path"
                )
            if execution_path in seen_execution_paths:
                raise ShadowError(
                    f"{context}: duplicate Linux procfd execution path"
                )
            seen_execution_paths.add(execution_path)
    return binding


def _validate_manifest_source_binding(
    declared: object,
    work: Mapping[str, Any],
    descriptor_binding: Mapping[str, Any],
) -> None:
    if type(declared) is not str or not declared:
        raise ShadowError("certificate manifest has invalid source path")
    binding = _validate_descriptor_binding(
        descriptor_binding, "certifier descriptor binding"
    )
    mechanism = binding["mechanism"]
    if mechanism == "platform_pathname":
        if canonical_nofollow_path(Path(declared)) != Path(work["source_path"]):
            raise ShadowError("certificate manifest source path mismatch")
        return
    if mechanism != "linux_procfd" or LINUX_PROC_FD.fullmatch(declared) is None:
        raise ShadowError(
            "certificate manifest source is not the sealed Linux descriptor path"
        )
    matches = [
        item
        for item in binding["files"]
        if item["path"] == work["source_path"]
        and item["sha256"] == work["source_sha256"]
    ]
    if len(matches) != 1:
        raise ShadowError(
            "certificate manifest source lacks its sealed descriptor binding"
        )
    if declared != matches[0]["execution_path"]:
        raise ShadowError(
            "certificate manifest source does not match its sealed source "
            "descriptor execution path"
        )


def validate_manifest_binding(
    manifest_path: Path,
    prefix: Path,
    work: Mapping[str, Any],
    descriptor_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify that the emitted manifest and artifacts are bound to this work item."""

    manifest = _read_manifest(manifest_path)
    if manifest.get("format") != "euf-viper-euf-cnf-v2":
        raise ShadowError("certificate manifest has unsupported format")
    if manifest.get("encoding") != "canonical-tseitin-v1":
        raise ShadowError("certificate manifest has unsupported encoding")
    if manifest.get("result") != work["expected_result"]:
        raise ShadowError(
            "certificate manifest result mismatch: "
            f"expected {work['expected_result']!r}, "
            f"got {manifest.get('result')!r}"
        )
    if manifest.get("source_sha256") != work["source_sha256"]:
        raise ShadowError("certificate manifest source SHA-256 mismatch")
    _validate_manifest_source_binding(
        manifest.get("source"), work, descriptor_binding
    )

    expected_dimacs = canonical_nofollow_path(Path(f"{prefix}.cnf"))
    expected_proof = canonical_nofollow_path(Path(f"{prefix}.drat"))
    if work["expected_result"] == "unsat":
        declared_dimacs = _resolve_declared_artifact(manifest.get("dimacs"), "DIMACS")
        declared_proof = _resolve_declared_artifact(manifest.get("proof"), "proof")
        if declared_dimacs != expected_dimacs or declared_proof != expected_proof:
            raise ShadowError("certificate manifest artifact path mismatch")
        for path, field, label in (
            (declared_dimacs, "dimacs_sha256", "DIMACS"),
            (declared_proof, "proof_sha256", "proof"),
        ):
            declared_hash = manifest.get(field)
            if not _is_sha256(declared_hash) or sha256_file(path) != declared_hash:
                raise ShadowError(f"certificate manifest {label} SHA-256 mismatch")
    else:
        if expected_dimacs.exists() or expected_proof.exists():
            raise ShadowError("SAT certification unexpectedly emitted UNSAT artifacts")
    return manifest


def _checker_payload(stdout_path: Path) -> dict[str, Any]:
    try:
        output_size = stdout_path.stat().st_size
    except OSError as error:
        raise ShadowError(
            f"cannot stat checker output {stdout_path}: {error}"
        ) from error
    if output_size > MAX_JSON_OUTPUT_BYTES:
        raise ShadowError("checker output exceeds the strict size limit")
    data = _read_output(stdout_path)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ShadowError(f"checker output is not UTF-8: {error}") from error
    value = _strict_json(text, "checker output")
    if type(value) is not dict:
        raise ShadowError("checker output must be one JSON object")
    return value


def validate_checker_binding(
    stdout_path: Path, work: Mapping[str, Any]
) -> dict[str, Any]:
    payload = _checker_payload(stdout_path)
    if payload.get("status") != "verified":
        raise ShadowError(
            f"checker did not report verified status: {payload.get('status')!r}"
        )
    if payload.get("result") != work["expected_result"]:
        raise ShadowError(
            f"checker result mismatch: expected {work['expected_result']!r}, "
            f"got {payload.get('result')!r}"
        )
    if payload.get("source_sha256") != work["source_sha256"]:
        raise ShadowError("checker source SHA-256 mismatch")
    return payload


def _certify_command(
    plan: Mapping[str, Any], work: Mapping[str, Any], prefix: Path
) -> list[str]:
    command = [
        plan["solver"]["path"],
        "certify",
        work["source_path"],
        "--out-prefix",
        str(prefix),
    ]
    rounds = plan["configuration"]["max_theory_rounds"]
    if rounds is not None:
        command.extend(["--max-theory-rounds", str(rounds)])
    return command


def _checker_command(
    plan: Mapping[str, Any],
    work: Mapping[str, Any],
    manifest_path: Path,
    prefix: Path,
) -> list[str]:
    command = [
        plan["python"]["path"],
        "-B",
        "-I",
        "-S",
        "-c",
        CHECKER_BOOTSTRAP,
        plan["checker"]["path"],
        plan["independent_parser"]["path"],
        str(manifest_path),
        "--source",
        work["source_path"],
    ]
    if work["expected_result"] == "unsat":
        drat = plan["drat_trim"]
        if drat is None:
            raise ShadowError("drat-trim is required for every UNSAT certificate")
        command.extend(
            [
                "--dimacs",
                f"{prefix}.cnf",
                "--proof",
                f"{prefix}.drat",
                "--drat-trim",
                drat["path"],
            ]
        )
    return command


def _attempt_layout(
    output_directory: Path, work: Mapping[str, Any], attempt: int
) -> tuple[Path, Path]:
    root = (
        output_directory
        / "artifacts"
        / work["work_sha256"]
        / f"attempt-{attempt:04d}"
    )
    return root, root / "certificate"


def _snapshot_drift(snapshots: Mapping[Path, str]) -> str | None:
    for path, expected in snapshots.items():
        try:
            actual = sha256_file(path)
        except ShadowError as error:
            return str(error)
        if actual != expected:
            return f"immutable input drift at {path}: expected {expected}, got {actual}"
    return None


def assert_unchanged(snapshots: Mapping[Path, str]) -> None:
    drift = _snapshot_drift(snapshots)
    if drift is not None:
        raise ShadowError(drift)


def _failure_from_process(
    label: str, process: Mapping[str, Any]
) -> tuple[str, str] | None:
    status = process["status"]
    if status == "interrupted":
        return "interrupted", f"{label} command was interrupted"
    if status == "timeout":
        return f"{label}_timeout", f"{label} command timed out"
    if status == "spawn_error":
        return f"{label}_spawn_error", f"cannot start {label}: {process['spawn_error']}"
    if status == "signal":
        return (
            f"{label}_signal",
            f"{label} terminated by signal {-process['exit_code']}",
        )
    if process["exit_code"] != 0:
        return f"{label}_exit", f"{label} exited with code {process['exit_code']}"
    return None


def execute_attempt(
    work: Mapping[str, Any],
    attempt: int,
    sequence: int,
    plan: Mapping[str, Any],
    *,
    output_directory: Path,
    certify_environment: Mapping[str, str],
    checker_environment: Mapping[str, str],
    snapshots: Mapping[Path, str],
) -> dict[str, Any]:
    attempt_directory, prefix = _attempt_layout(output_directory, work, attempt)
    artifacts_directory = output_directory / "artifacts"
    if artifacts_directory.is_symlink():
        raise ShadowError(f"artifact root is a symlink: {artifacts_directory}")
    artifacts_directory.mkdir(exist_ok=True)
    if not artifacts_directory.is_dir():
        raise ShadowError(f"artifact root is not a directory: {artifacts_directory}")
    work_directory = attempt_directory.parent
    if work_directory.is_symlink():
        raise ShadowError(f"artifact work directory is a symlink: {work_directory}")
    work_directory.mkdir(exist_ok=True)
    if not work_directory.is_dir():
        raise ShadowError(f"artifact work path is not a directory: {work_directory}")
    try:
        attempt_directory.mkdir()
    except FileExistsError as error:
        raise ShadowError(
            f"unjournaled or duplicate attempt directory exists: {attempt_directory}"
        ) from error

    certify_stdout = attempt_directory / "certify.stdout"
    certify_stderr = attempt_directory / "certify.stderr"
    certify_command = _certify_command(plan, work, prefix)
    started_at = _utc_now()
    certify_process = run_cold_process(
        certify_command,
        environment=certify_environment,
        timeout_s=plan["configuration"]["timeout_s"],
        grace_s=plan["configuration"]["timeout_grace_s"],
        stdout_path=certify_stdout,
        stderr_path=certify_stderr,
        output_directory=output_directory,
        descriptor_hashes={
            plan["solver"]["path"]: plan["solver"]["sha256"],
            work["source_path"]: work["source_sha256"],
        },
    )

    checker_command: list[str] | None = None
    checker_process: dict[str, Any] | None = None
    failure = _failure_from_process("certify", certify_process)
    manifest_path = Path(f"{prefix}.euf.json")

    if failure is None:
        token, token_status = _certify_result(certify_stdout)
        if token_status == "abstention":
            failure = (
                "certify_abstention",
                f"certifier abstained with {token!r}; abstention is never verified",
            )
        elif token_status != "decisive":
            failure = (
                "certify_output",
                "certifier did not emit exactly one sat or unsat result token",
            )
        elif token != work["expected_result"]:
            failure = (
                "result_mismatch",
                "certifier result mismatch: "
                f"expected {work['expected_result']!r}, got {token!r}",
            )

    if failure is None:
        try:
            validate_manifest_binding(
                manifest_path,
                prefix,
                work,
                certify_process["descriptor_binding"],
            )
        except ShadowError as error:
            kind = (
                "manifest_missing"
                if not manifest_path.is_file()
                else "manifest_mismatch"
            )
            failure = (kind, str(error))

    if failure is None:
        drift = _snapshot_drift(snapshots)
        if drift is not None:
            failure = ("input_drift", drift)

    if failure is None:
        checker_command = _checker_command(plan, work, manifest_path, prefix)
        checker_process = run_cold_process(
            checker_command,
            environment=checker_environment,
            timeout_s=plan["configuration"]["checker_timeout_s"],
            grace_s=plan["configuration"]["timeout_grace_s"],
            stdout_path=attempt_directory / "checker.stdout",
            stderr_path=attempt_directory / "checker.stderr",
            output_directory=output_directory,
            descriptor_hashes={
                plan["python"]["path"]: plan["python"]["sha256"],
                plan["checker"]["path"]: plan["checker"]["sha256"],
                plan["independent_parser"]["path"]: plan["independent_parser"]["sha256"],
                work["source_path"]: work["source_sha256"],
                str(manifest_path): sha256_file(manifest_path),
                **(
                    {
                        f"{prefix}.cnf": sha256_file(Path(f"{prefix}.cnf")),
                        f"{prefix}.drat": sha256_file(Path(f"{prefix}.drat")),
                        plan["drat_trim"]["path"]: plan["drat_trim"]["sha256"],
                    }
                    if work["expected_result"] == "unsat"
                    else {}
                ),
            },
        )
        failure = _failure_from_process("checker", checker_process)
        if failure is None:
            try:
                validate_manifest_binding(
                    manifest_path,
                    prefix,
                    work,
                    certify_process["descriptor_binding"],
                )
                validate_checker_binding(
                    _artifact_absolute(
                        checker_process["stdout_path"], output_directory
                    ),
                    work,
                )
            except ShadowError as error:
                message = str(error)
                kind = (
                    "checker_mismatch"
                    if "mismatch" in message or "verified" in message
                    else "checker_output"
                )
                failure = (kind, message)

    if failure is None:
        drift = _snapshot_drift(snapshots)
        if drift is not None:
            failure = ("input_drift", drift)

    artifacts = _collect_artifacts(prefix, output_directory)
    verified = failure is None
    finished_at = _utc_now()
    record: dict[str, Any] = {
        "record_type": "attempt",
        "schema_version": SCHEMA_VERSION,
        "parent_lock_sha256": work["parent_lock_sha256"],
        "plan_sha256": plan["record_sha256"],
        "sequence": sequence,
        "work_index": work["global_index"],
        "work_sha256": work["work_sha256"],
        "attempt": attempt,
        "instance_id": work["instance_id"],
        "relative_path": work["relative_path"],
        "source_path": work["source_path"],
        "source_sha256": work["source_sha256"],
        "solver_sha256": work["solver_sha256"],
        "expected_result": work["expected_result"],
        "started_at": started_at,
        "finished_at": finished_at,
        "certify_command": certify_command,
        "checker_command": checker_command,
        "certify_process": certify_process,
        "checker_process": checker_process,
        "artifacts": artifacts,
        "verified": verified,
        "failure_kind": failure[0] if failure is not None else None,
        "failure_message": failure[1] if failure is not None else None,
    }
    return record


def _validate_process_record(
    process: object, context: str, output_directory: Path
) -> dict[str, Any]:
    value = _require_exact_keys(process, PROCESS_KEYS, context)
    if value["status"] not in {
        "exit",
        "signal",
        "timeout",
        "spawn_error",
        "interrupted",
    }:
        raise ShadowError(f"{context}: invalid process status")
    if value["exit_code"] is not None and type(value["exit_code"]) is not int:
        raise ShadowError(f"{context}: exit_code must be integer or null")
    if value["status"] == "exit" and (
        type(value["exit_code"]) is not int or value["exit_code"] < 0
    ):
        raise ShadowError(f"{context}: exit status requires a non-negative code")
    if value["status"] == "signal" and (
        type(value["exit_code"]) is not int or value["exit_code"] >= 0
    ):
        raise ShadowError(f"{context}: signal status requires a negative code")
    if value["status"] == "spawn_error" and value["exit_code"] is not None:
        raise ShadowError(f"{context}: spawn failure cannot have an exit code")
    if value["status"] in {"timeout", "interrupted"} and type(
        value["exit_code"]
    ) is not int:
        raise ShadowError(f"{context}: terminated process must have an exit code")
    if type(value["timed_out"]) is not bool or value["timed_out"] != (
        value["status"] == "timeout"
    ):
        raise ShadowError(f"{context}: timeout fields disagree")
    if (value["spawn_error"] is not None) != (value["status"] == "spawn_error"):
        raise ShadowError(f"{context}: spawn-error fields disagree")
    if value["spawn_error"] is not None and (
        type(value["spawn_error"]) is not str or not value["spawn_error"]
    ):
        raise ShadowError(f"{context}: invalid spawn_error")
    _validate_descriptor_binding(
        value["descriptor_binding"], f"{context} descriptor binding"
    )
    wall = value["wall_time_s"]
    if type(wall) not in {int, float} or not math.isfinite(wall) or wall < 0:
        raise ShadowError(f"{context}: invalid wall_time_s")
    for stream in ("stdout", "stderr"):
        relative = value[f"{stream}_path"]
        if type(relative) is not str:
            raise ShadowError(f"{context}: invalid {stream}_path")
        path = _artifact_absolute(relative, output_directory)
        actual_hash, actual_bytes, actual_excerpt = _inspect_output(path)
        if value[f"{stream}_sha256"] != actual_hash:
            raise ShadowError(f"{context}: {stream} SHA-256 drift")
        if value[f"{stream}_bytes"] != actual_bytes:
            raise ShadowError(f"{context}: {stream} byte-count drift")
        if value[f"{stream}_excerpt"] != actual_excerpt:
            raise ShadowError(f"{context}: {stream} excerpt drift")
    return value


def _validate_artifacts(
    artifacts: object,
    prefix: Path,
    output_directory: Path,
    context: str,
) -> dict[str, Any]:
    value = _require_exact_keys(artifacts, ARTIFACT_KEYS, context)
    expected_paths = _known_artifact_paths(prefix, output_directory)
    for label in ("manifest", "dimacs", "proof"):
        path_field = f"{label}_path"
        hash_field = f"{label}_sha256"
        if value[path_field] != expected_paths[path_field]:
            raise ShadowError(f"{context}: {label} path drift")
        path = _artifact_absolute(value[path_field], output_directory)
        if path.is_symlink():
            raise ShadowError(f"{context}: {label} artifact is a symlink")
        declared = value[hash_field]
        if path.is_file():
            if not _is_sha256(declared) or sha256_file(path) != declared:
                raise ShadowError(f"{context}: {label} SHA-256 drift")
        elif declared is not None:
            raise ShadowError(f"{context}: missing {label} has a declared hash")
    return value


def validate_attempt_record(
    record: object,
    work: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    expected_sequence: int,
    expected_attempt: int,
    output_directory: Path,
) -> dict[str, Any]:
    context = f"journal attempt sequence {expected_sequence}"
    value = _require_exact_keys(record, ATTEMPT_KEYS, context)
    expected_static = {
        "record_type": "attempt",
        "schema_version": SCHEMA_VERSION,
        "parent_lock_sha256": work["parent_lock_sha256"],
        "plan_sha256": plan["record_sha256"],
        "sequence": expected_sequence,
        "work_index": work["global_index"],
        "work_sha256": work["work_sha256"],
        "attempt": expected_attempt,
        "instance_id": work["instance_id"],
        "relative_path": work["relative_path"],
        "source_path": work["source_path"],
        "source_sha256": work["source_sha256"],
        "solver_sha256": work["solver_sha256"],
        "expected_result": work["expected_result"],
    }
    for field, expected in expected_static.items():
        if canonical_bytes(value[field]) != canonical_bytes(expected):
            raise ShadowError(f"{context}: static field {field!r} drift")
    for field in ("started_at", "finished_at"):
        if type(value[field]) is not str or not value[field]:
            raise ShadowError(f"{context}: {field} must be non-empty")

    attempt_directory, prefix = _attempt_layout(
        output_directory, work, expected_attempt
    )
    expected_certify = _certify_command(plan, work, prefix)
    if value["certify_command"] != expected_certify:
        raise ShadowError(f"{context}: certify command drift")
    certify = _validate_process_record(
        value["certify_process"], f"{context} certify process", output_directory
    )
    checker = None
    if value["checker_process"] is not None:
        checker = _validate_process_record(
            value["checker_process"], f"{context} checker process", output_directory
        )
        expected_checker = _checker_command(
            plan, work, Path(f"{prefix}.euf.json"), prefix
        )
        if value["checker_command"] != expected_checker:
            raise ShadowError(f"{context}: checker command drift")
    elif value["checker_command"] is not None:
        raise ShadowError(f"{context}: checker command exists without a process")
    artifacts = _validate_artifacts(
        value["artifacts"], prefix, output_directory, f"{context} artifacts"
    )

    if type(value["verified"]) is not bool:
        raise ShadowError(f"{context}: verified must be a boolean")
    if value["verified"]:
        if value["failure_kind"] is not None or value["failure_message"] is not None:
            raise ShadowError(f"{context}: verified attempt has a failure")
        if _failure_from_process("certify", certify) is not None:
            raise ShadowError(f"{context}: verified certifier process was unsuccessful")
        if checker is None or _failure_from_process("checker", checker) is not None:
            raise ShadowError(f"{context}: verified checker process was unsuccessful")
        token, token_status = _certify_result(
            _artifact_absolute(certify["stdout_path"], output_directory)
        )
        if token_status != "decisive" or token != work["expected_result"]:
            raise ShadowError(f"{context}: verified certifier result is not matching")
        validate_manifest_binding(
            Path(f"{prefix}.euf.json"),
            prefix,
            work,
            certify["descriptor_binding"],
        )
        validate_checker_binding(
            _artifact_absolute(checker["stdout_path"], output_directory), work
        )
        if not _is_sha256(artifacts["manifest_sha256"]):
            raise ShadowError(f"{context}: verified attempt lacks a manifest")
        if work["expected_result"] == "unsat" and (
            not _is_sha256(artifacts["dimacs_sha256"])
            or not _is_sha256(artifacts["proof_sha256"])
        ):
            raise ShadowError(
                f"{context}: verified UNSAT attempt lacks proof artifacts"
            )
    else:
        if value["failure_kind"] not in FAILURE_KINDS:
            raise ShadowError(f"{context}: invalid failure kind")
        if type(value["failure_message"]) is not str or not value["failure_message"]:
            raise ShadowError(f"{context}: failed attempt lacks a message")
    return value


def _fsync_parent(path: Path) -> None:
    try:
        fsync_parent_nofollow(path, f"shadow journal {path}")
    except StrictArtifactError as error:
        raise ShadowError(str(error)) from error


class Journal:
    """Locked append-only canonical JSONL journal with an exact hash chain."""

    def __init__(self, path: Path, expected_plan: dict[str, Any]) -> None:
        self.path = path
        self.expected_plan = expected_plan
        self.fd: int | None = None
        self.records: list[dict[str, Any]] = []
        self.attempts: list[dict[str, Any]] = []
        self.last_hash: str | None = None

    def __enter__(self) -> "Journal":
        try:
            self.path, self.fd = open_append_nofollow(
                self.path, f"shadow journal {self.path}"
            )
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _fsync_parent(self.path)
        except BlockingIOError as error:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            raise ShadowError(
                f"journal is locked by another process: {self.path}"
            ) from error
        except (OSError, StrictArtifactError) as error:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            raise ShadowError(f"cannot open journal {self.path}: {error}") from error
        self._load()
        if not self.records:
            self._append_complete(self.expected_plan)
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

    def sha256(self) -> str:
        assert self.fd is not None
        try:
            assert_descriptor_path_nofollow(
                self.path, self.fd, f"shadow journal {self.path}"
            )
            content = self._read_all()
            assert_descriptor_path_nofollow(
                self.path, self.fd, f"shadow journal {self.path}"
            )
        except StrictArtifactError as error:
            raise ShadowError(str(error)) from error
        return sha256_bytes(content)

    def _load(self) -> None:
        raw = self._read_all()
        if not raw:
            return
        if not raw.endswith(b"\n"):
            raise ShadowError(
                f"journal {self.path} ends with an incomplete frame; ordinary resume refuses recovery"
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ShadowError(f"journal is not UTF-8: {error}") from error
        previous: str | None = None
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line:
                raise ShadowError(f"journal {self.path}:{line_number} is blank")
            value = _strict_json(line, f"journal {self.path}:{line_number}")
            if type(value) is not dict:
                raise ShadowError(
                    f"journal {self.path}:{line_number} must be an object"
                )
            if canonical_bytes(value) != (line + "\n").encode("utf-8"):
                raise ShadowError(
                    f"journal {self.path}:{line_number} is not canonical immutable JSON"
                )
            if value.get("previous_record_sha256") != previous:
                raise ShadowError(
                    f"journal {self.path}:{line_number} breaks the hash chain"
                )
            record_hash = value.get("record_sha256")
            if not _is_sha256(record_hash) or _record_digest(value) != record_hash:
                raise ShadowError(
                    f"journal {self.path}:{line_number} record hash drift"
                )
            if line_number == 1:
                if canonical_bytes(value) != canonical_bytes(self.expected_plan):
                    raise ShadowError(
                        "existing journal plan does not match this invocation"
                    )
            elif value.get("record_type") != "attempt":
                raise ShadowError(
                    f"journal {self.path}:{line_number} has invalid record type"
                )
            self.records.append(value)
            if value.get("record_type") == "attempt":
                self.attempts.append(value)
            previous = record_hash
        self.last_hash = previous

    def _append_complete(self, complete: Mapping[str, Any]) -> dict[str, Any]:
        assert self.fd is not None
        encoded = canonical_bytes(complete)
        offset = 0
        while offset < len(encoded):
            written = os.write(self.fd, encoded[offset:])
            if written <= 0:
                raise ShadowError(f"short append to journal {self.path}")
            offset += written
        os.fsync(self.fd)
        value = dict(complete)
        self.records.append(value)
        if value["record_type"] == "attempt":
            self.attempts.append(value)
        self.last_hash = value["record_sha256"]
        return value

    def append_attempt(self, record: Mapping[str, Any]) -> dict[str, Any]:
        complete = dict(record)
        complete["previous_record_sha256"] = self.last_hash
        complete["record_sha256"] = _record_digest(complete)
        return self._append_complete(complete)


def validate_journal_attempts(
    journal: Journal,
    shard_works: Sequence[dict[str, Any]],
    plan: Mapping[str, Any],
    output_directory: Path,
) -> tuple[dict[str, dict[str, Any]], collections.Counter[str]]:
    by_hash = {work["work_sha256"]: work for work in shard_works}
    attempt_counts: collections.Counter[str] = collections.Counter()
    latest: dict[str, dict[str, Any]] = {}
    verified: set[str] = set()
    work_position = 0
    for sequence, record in enumerate(journal.attempts):
        if work_position >= len(shard_works):
            raise ShadowError("journal contains attempts after the shard was complete")
        scheduled_work = shard_works[work_position]
        work_hash = record.get("work_sha256")
        work = by_hash.get(work_hash)
        if work is None:
            raise ShadowError(
                f"journal attempt {sequence} is not in this shard workset"
            )
        if work_hash != scheduled_work["work_sha256"]:
            raise ShadowError(
                f"journal attempt {sequence} is not the next exact shard work item"
            )
        if work_hash in verified:
            raise ShadowError(
                f"journal contains an attempt after verification for {work_hash}"
            )
        expected_attempt = attempt_counts[work_hash] + 1
        validated = validate_attempt_record(
            record,
            work,
            plan,
            expected_sequence=sequence,
            expected_attempt=expected_attempt,
            output_directory=output_directory,
        )
        attempt_counts[work_hash] = expected_attempt
        latest[work_hash] = validated
        if validated["verified"]:
            verified.add(work_hash)
            work_position += 1
    return latest, attempt_counts


def _atomic_write(
    path: Path,
    content: bytes,
    *,
    pre_publish: Any | None = None,
) -> None:
    try:
        atomic_write_nofollow(
            path,
            content,
            f"shadow summary {path}",
            immutable=False,
            pre_publish=pre_publish,
        )
    except StrictArtifactError as error:
        raise ShadowError(str(error)) from error


def build_summary(
    journal: Journal,
    plan: Mapping[str, Any],
    shard_works: Sequence[dict[str, Any]],
    *,
    journal_path: Path,
    status_override: str | None = None,
) -> dict[str, Any]:
    latest: dict[str, dict[str, Any]] = {}
    for attempt in journal.attempts:
        latest[attempt["work_sha256"]] = attempt
    verified = [
        work
        for work in shard_works
        if latest.get(work["work_sha256"], {}).get("verified") is True
    ]
    failed = [
        work
        for work in shard_works
        if work["work_sha256"] in latest
        and not latest[work["work_sha256"]]["verified"]
    ]
    pending = [
        work for work in shard_works if work["work_sha256"] not in latest
    ]
    status = status_override
    if status is None:
        if len(verified) == len(shard_works):
            status = "complete"
        elif failed:
            status = "failed"
        else:
            status = "in_progress"
    failure_counts = collections.Counter(
        latest[work["work_sha256"]]["failure_kind"] for work in failed
    )
    historical_failures = collections.Counter(
        attempt["failure_kind"]
        for attempt in journal.attempts
        if not attempt["verified"]
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "campaign_id": plan["campaign_id"],
        "parent_lock_sha256": plan["parent_lock_sha256"],
        "parent_lock_file_sha256": plan["parent_lock_file_sha256"],
        "parent_raw_sha256": plan["parent_raw_sha256"],
        "plan_sha256": plan["record_sha256"],
        "solver": plan["solver"],
        "python": plan.get("python"),
        "checker": plan["checker"],
        "independent_parser": plan.get("independent_parser"),
        "drat_trim": plan["drat_trim"],
        "selection": plan["selection"],
        "counts": {
            "attempts": len(journal.attempts),
            "verified_instances": len(verified),
            "failed_instances": len(failed),
            "pending_instances": len(pending),
        },
        "verified_results": dict(
            sorted(
                collections.Counter(
                    work["expected_result"] for work in verified
                ).items()
            )
        ),
        "failure_counts": dict(sorted(failure_counts.items())),
        "historical_failure_counts": dict(sorted(historical_failures.items())),
        "verified": [
            {
                "global_index": work["global_index"],
                "relative_path": work["relative_path"],
                "result": work["expected_result"],
                "work_sha256": work["work_sha256"],
                "attempt": latest[work["work_sha256"]]["attempt"],
                "artifacts": latest[work["work_sha256"]]["artifacts"],
            }
            for work in verified
        ],
        "failed": [
            {
                "global_index": work["global_index"],
                "relative_path": work["relative_path"],
                "work_sha256": work["work_sha256"],
                "attempt": latest[work["work_sha256"]]["attempt"],
                "failure_kind": latest[work["work_sha256"]]["failure_kind"],
                "failure_message": latest[work["work_sha256"]]["failure_message"],
            }
            for work in failed
        ],
        "pending": [work["relative_path"] for work in pending],
        "journal": str(journal_path),
        "journal_sha256": journal.sha256(),
        "journal_record_chain_head": journal.last_hash,
    }


def _write_summary(
    path: Path,
    journal: Journal,
    plan: Mapping[str, Any],
    shard_works: Sequence[dict[str, Any]],
    *,
    status_override: str | None = None,
    pre_publish: Any | None = None,
) -> dict[str, Any]:
    summary = build_summary(
        journal,
        plan,
        shard_works,
        journal_path=journal.path,
        status_override=status_override,
    )
    _atomic_write(path, canonical_bytes(summary), pre_publish=pre_publish)
    return summary


def _validate_output_paths(
    output_directory: Path,
    journal_path: Path,
    summary_path: Path,
    protected: Sequence[Path],
) -> None:
    if journal_path == summary_path:
        raise ShadowError("journal and summary paths must be different")
    for path in (journal_path, summary_path):
        if path in protected:
            raise ShadowError(f"output path would overwrite immutable input: {path}")
    try:
        ensure_directory_nofollow(output_directory, "shadow output directory")
        ensure_parent_directory_nofollow(journal_path, "shadow journal")
        ensure_parent_directory_nofollow(summary_path, "shadow summary")
    except StrictArtifactError as error:
        raise ShadowError(str(error)) from error


def run_shadow_campaign(
    lock_path: Path,
    raw_path: Path,
    *,
    output_directory: Path,
    binary: str | Path | None = None,
    checker: str | Path = DEFAULT_CHECKER,
    drat_trim: str | Path | None = None,
    corpus_root: Path | None = None,
    timeout_s: float = 60.0,
    checker_timeout_s: float | None = None,
    timeout_grace_s: float = 0.25,
    max_theory_rounds: int | None = None,
    shard_index: int = 0,
    shard_count: int = 1,
    journal_path: Path | None = None,
    summary_path: Path | None = None,
) -> dict[str, Any]:
    if os.name != "posix" or not hasattr(os, "killpg"):
        raise ShadowError("strict process-group cleanup requires a POSIX host")
    if not math.isfinite(timeout_s) or timeout_s <= 0:
        raise ShadowError("timeout must be finite and greater than zero")
    if checker_timeout_s is None:
        checker_timeout_s = timeout_s
    if not math.isfinite(checker_timeout_s) or checker_timeout_s <= 0:
        raise ShadowError("checker timeout must be finite and greater than zero")
    if not math.isfinite(timeout_grace_s) or timeout_grace_s < 0:
        raise ShadowError("timeout grace must be finite and non-negative")
    if max_theory_rounds is not None and (
        type(max_theory_rounds) is not int or max_theory_rounds < 1
    ):
        raise ShadowError("max theory rounds must be at least one")

    lock_path = canonical_nofollow_path(lock_path)
    raw_path = canonical_nofollow_path(raw_path)
    if corpus_root is not None:
        try:
            corpus_root = ensure_directory_nofollow(corpus_root, "shadow corpus root")
        except StrictArtifactError as error:
            raise ShadowError(str(error)) from error

    campaign = load_validated_campaign(lock_path, raw_path)
    works = derive_work_records(campaign, lock_path, corpus_root=corpus_root)
    shard_works = partition_work_records(works, shard_index, shard_count)
    locked_solver = _candidate_solver(campaign["lock"])
    solver_path = resolve_executable(
        binary or locked_solver["binary"], "euf-viper binary"
    )
    actual_solver_hash = sha256_file(solver_path)
    if actual_solver_hash != locked_solver["sha256"]:
        raise ShadowError(
            f"euf-viper binary SHA-256 mismatch: locked {locked_solver['sha256']}, "
            f"actual {actual_solver_hash}"
        )
    checker_path = resolve_executable(checker, "certificate checker")
    python_path = resolve_executable(sys.executable, "Python interpreter")
    independent_parser_path = canonical_nofollow_path(INDEPENDENT_PARSER_PATH)

    selected_has_unsat = any(work["expected_result"] == "unsat" for work in shard_works)
    if drat_trim is None and selected_has_unsat:
        raise ShadowError(
            "drat-trim is required for selected UNSAT work; pass --drat-trim PATH"
        )
    drat_trim_path = (
        resolve_executable(drat_trim, "drat-trim") if drat_trim is not None else None
    )

    certify_environment = dict(campaign["lock"]["execution"]["environment"])
    certify_environment.update(locked_solver["environment"])
    checker_environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", os.defpath),
        "TZ": "UTC",
    }

    output_directory = canonical_nofollow_path(output_directory)
    default_stem = f"shard-{shard_index:04d}-of-{shard_count:04d}"
    journal_path = (
        canonical_nofollow_path(journal_path)
        if journal_path is not None
        else output_directory / f"{default_stem}.journal.jsonl"
    )
    summary_path = (
        canonical_nofollow_path(summary_path)
        if summary_path is not None
        else output_directory / f"{default_stem}.summary.json"
    )
    protected = [
        lock_path,
        raw_path,
        solver_path,
        python_path,
        checker_path,
        independent_parser_path,
    ]
    if drat_trim_path is not None:
        protected.append(drat_trim_path)
    protected.extend(Path(work["source_path"]) for work in works)
    _validate_output_paths(
        output_directory, journal_path, summary_path, protected
    )

    plan = build_plan_record(
        campaign,
        works,
        shard_works,
        solver_path=solver_path,
        python_path=python_path,
        checker_path=checker_path,
        independent_parser_path=independent_parser_path,
        drat_trim_path=drat_trim_path,
        corpus_root=corpus_root,
        timeout_s=timeout_s,
        checker_timeout_s=checker_timeout_s,
        timeout_grace_s=timeout_grace_s,
        max_theory_rounds=max_theory_rounds,
        shard_index=shard_index,
        shard_count=shard_count,
        certify_environment=certify_environment,
        checker_environment=checker_environment,
    )
    snapshots: dict[Path, str] = {
        lock_path: campaign["lock_file_sha256"],
        raw_path: campaign["raw_sha256"],
        solver_path: locked_solver["sha256"],
        python_path: plan["python"]["sha256"],
        checker_path: plan["checker"]["sha256"],
        independent_parser_path: plan["independent_parser"]["sha256"],
    }
    if drat_trim_path is not None:
        snapshots[drat_trim_path] = plan["drat_trim"]["sha256"]
    for work in shard_works:
        snapshots[Path(work["source_path"])] = work["source_sha256"]
    assert_unchanged(snapshots)

    with Journal(journal_path, plan) as journal:
        _write_summary(
            summary_path,
            journal,
            plan,
            shard_works,
            status_override="in_progress",
        )
        rehash_production_evidence(shard_works)
        latest, attempt_counts = validate_journal_attempts(
            journal, shard_works, plan, output_directory
        )
        assert_unchanged(snapshots)
        for work in shard_works:
            prior = latest.get(work["work_sha256"])
            if prior is not None and prior["verified"]:
                continue
            attempt = attempt_counts[work["work_sha256"]] + 1
            record = execute_attempt(
                work,
                attempt,
                len(journal.attempts),
                plan,
                output_directory=output_directory,
                certify_environment=certify_environment,
                checker_environment=checker_environment,
                snapshots=snapshots,
            )
            completed = journal.append_attempt(record)
            latest[work["work_sha256"]] = completed
            attempt_counts[work["work_sha256"]] = attempt
            if completed["verified"]:
                assert_unchanged(snapshots)
                _write_summary(
                    summary_path,
                    journal,
                    plan,
                    shard_works,
                    status_override="in_progress",
                )
                print(
                    f"[{work['global_index'] + 1}/{len(works)}] "
                    f"{work['relative_path']} verified {work['expected_result']}",
                    flush=True,
                )
                continue

            status = (
                "interrupted"
                if completed["failure_kind"] == "interrupted"
                else "failed"
            )
            _write_summary(
                summary_path,
                journal,
                plan,
                shard_works,
                status_override=status,
            )
            message = (
                f"{work['relative_path']}: {completed['failure_kind']}: "
                f"{completed['failure_message']}"
            )
            if completed["failure_kind"] == "interrupted":
                raise ShadowInterrupted(message)
            raise ShadowError(message)

        def final_rehash() -> None:
            rehash_production_evidence(shard_works)
            assert_unchanged(snapshots)

        return _write_summary(
            summary_path,
            journal,
            plan,
            shard_works,
            pre_publish=final_rehash,
        )


def _positive_float(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return value


def _nonnegative_float(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError("must be finite and non-negative")
    return value


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least one")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path, help="validated campaign lock JSON")
    parser.add_argument("raw", type=Path, help="complete locked raw JSONL")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--binary", "--euf-viper", dest="binary")
    parser.add_argument("--checker", default=str(DEFAULT_CHECKER))
    parser.add_argument("--drat-trim")
    parser.add_argument("--corpus-root", type=Path)
    parser.add_argument("--timeout", "--timeout-s", type=_positive_float, default=60.0)
    parser.add_argument("--checker-timeout", type=_positive_float)
    parser.add_argument("--timeout-grace", type=_nonnegative_float, default=0.25)
    parser.add_argument("--max-theory-rounds", type=_positive_int)
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=_positive_int, default=1)
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--summary", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = run_shadow_campaign(
            args.lock,
            args.raw,
            output_directory=args.output_dir,
            binary=args.binary,
            checker=args.checker,
            drat_trim=args.drat_trim,
            corpus_root=args.corpus_root,
            timeout_s=args.timeout,
            checker_timeout_s=args.checker_timeout,
            timeout_grace_s=args.timeout_grace,
            max_theory_rounds=args.max_theory_rounds,
            shard_index=args.shard_index,
            shard_count=args.shard_count,
            journal_path=args.journal,
            summary_path=args.summary,
        )
    except ShadowInterrupted as error:
        print(f"certificate shadow interrupted: {error}", file=sys.stderr)
        return 130
    except ShadowError as error:
        print(f"certificate shadow failed: {error}", file=sys.stderr)
        return 2
    print(
        f"certificate shadow complete: "
        f"verified={summary['counts']['verified_instances']} "
        f"shard={summary['selection']['shard_index']}/"
        f"{summary['selection']['shard_count']} journal={summary['journal']}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
