#!/usr/bin/env python3
"""Validate and seal a non-authorizing T11 Stage 0A projection candidate."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import re
import stat
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA = "euf-viper.t11-stage0a-validation-candidate.v2"
LAUNCH_SCHEMA = "euf-viper.t11-stage0a-launch.v6"
PREBUILT_BUNDLE_SCHEMA = "euf-viper.t11-prebuilt-bundle.v1"
BUILD_RECEIPT_SCHEMA = "euf-viper.t11-prebuilt-build-receipt.v1"
DEPENDENCY_INVENTORY_SCHEMA = "euf-viper.t11-binary-dependencies.v1"
PREBUILT_PREPARATION_SCHEMA = "euf-viper.t11-prebuilt-preparation.v2"
PREBUILT_BUILD_COMMAND = [
    "cargo",
    "build",
    "--locked",
    "--features",
    "certificates",
    "--release",
    "--target",
    "x86_64-unknown-linux-gnu",
]
TARGET_RELATIVE_PATH = (
    "QF_UF/2018-Goel-hwbench/"
    "QF_UF_sokoban.2.prop1_ab_br_max.smt2"
)
TARGET_SHA256 = "cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112"
ROOT_CNF_MODE_SHA256 = hashlib.sha256(
    b"direct-root;negated-root=false;v1"
).hexdigest()
ATOM_MAP_SHA256 = "2fa9cabb8279cf59a9ca73cd254c0c60fe028753e8aa01d1794dd0c645167496"
BASELINE_CNF_SHA256 = "adb6885f8ee5d5230e81a3293d183bd4ae14d985f3df5bba9bc6c9fcd9fb1bb0"
BASELINE_PROBLEM_SHA256 = (
    "652e7b303accb7396dd9dfd5fdf40d17abd523f4a87897609390b6aa94d33597"
)
ZERO_SHA256 = "0" * 64
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")

EXPECTED_INPUT_COUNTERS = {
    "terms": 8_682,
    "baseline_variables": 21_744,
    "baseline_atom_entries": 18_082,
    "baseline_clauses": 89_470,
    "baseline_literal_slots": 147_132,
    "applications": 138,
    "application_pairs": 3_686,
    "maximum_arity": 2,
    "application_argument_slots": 268,
}
EXPECTED_SELECTOR_FACTS = {
    "finite_added_clauses": 0,
    "covered_finite_terms": 0,
    "closed_table_functions": 0,
    "all_different_clique_lower_bound": 60,
    "disequality_graph_edges": 1_773,
    "equality_graph_vertices": 4_838,
    "equality_graph_edges": 14_241,
    "applications": 138,
    "boolean_valued_application_pairs": 0,
    "backend": "kissat",
}

SEARCH_LIMITS = {
    "accepted_equality_nodes": 100_000,
    "accepted_conflict_clauses": 25_000,
    "proof_parent_references": 300_000,
    "maximum_proof_depth": 256,
    "accepted_trace_literal_slots": 150_000,
    "canonical_proof_work_literal_charge": 2_000_000,
    "worklist_pushes": 250_000,
    "live_worklist_entries": 65_536,
    "peak_live_worklist_entries": 65_536,
    "logical_incremental_memory_bytes": 16 * 1024 * 1024,
}
MEMORY_WEIGHTS = {
    "accepted_equality_nodes": 64,
    "accepted_conflict_clauses": 32,
    "proof_parent_references": 4,
    "accepted_trace_literal_slots": 4,
    "distinct_event_keys_inserted": 64,
    "peak_retained_antichain_entries": 16,
    "registered_negative_equality_occurrences": 16,
}

HASH_FIELDS = (
    "source_sha256",
    "root_cnf_mode_sha256",
    "term_dag_sha256",
    "atom_map_sha256",
    "baseline_cnf_sha256",
    "baseline_problem_sha256",
    "trace_sha256",
    "lemma_sequence_sha256",
    "materialized_lemmas_sha256",
    "materialized_candidate_sha256",
    "candidate_binary_sha256",
    "revision_sha256",
    "corpus_manifest_sha256",
    "projection_record_sha256",
    "checker_record_sha256",
    "observation_record_sha256",
    "dimacs_sha256",
    "invocation_sha256",
    "drat_sha256",
)
INTERNAL_HASH_FIELDS = HASH_FIELDS[:10]
EXTERNAL_HASH_FIELDS = HASH_FIELDS[10:]
RULE_COUNTER_FIELDS = (
    "seed",
    "reflexivity",
    "transitivity",
    "congruence",
    "conflict",
)
INPUT_COUNTER_FIELDS = (
    "terms",
    "baseline_variables",
    "baseline_atom_entries",
    "baseline_clauses",
    "baseline_literal_slots",
    "applications",
    "application_pairs",
    "maximum_arity",
    "application_argument_slots",
)
SEARCH_COUNTER_FIELDS = (
    "attempted_events",
    "accepted_events",
    "events_popped",
    "distinct_event_keys_inserted",
    "duplicate_event_keys",
    "worklist_pushes",
    "live_worklist_entries",
    "peak_live_worklist_entries",
    "queued_events_discarded_at_theory_empty",
    "accepted_equality_nodes",
    "accepted_conflict_clauses",
    "proof_parent_references",
    "maximum_proof_depth",
    "accepted_trace_literal_slots",
    "canonical_proof_work_literal_charge",
    "retained_antichain_entries",
    "peak_retained_antichain_entries",
    "registered_negative_equality_occurrences",
    "logical_incremental_memory_bytes",
    "suppressed_missing_equality_congruence_events",
)
PRUNING_COUNTER_FIELDS = (
    "support_subset_discards",
    "support_capacity_discards",
    "support_removed_supersets",
    "duplicate_derived_clauses",
    "tautological_derived_clauses",
    "final_base_subsumption_discards",
    "final_output_subsumption_discards",
)
OUTPUT_COUNTER_FIELDS = (
    "emitted_lemmas",
    "emitted_literal_slots",
    "emitted_p95_width",
    "emitted_maximum_width",
    "emitted_with_missing_equality_congruence",
)
CHECKER_COUNTER_FIELDS = (
    "replayed_equality_nodes",
    "replayed_conflict_clauses",
    "replayed_emitted_lemmas",
    "replay_failures",
)
FORBIDDEN_GROWTH_FIELDS = (
    "added_terms",
    "added_atoms",
    "added_variables",
    "fill_edges",
    "generic_transitivity_clauses",
)
INTEGRITY_FIELDS = (
    "baseline_unchanged",
    "trace_materialization_equal",
    "compiler_checker_agree",
    "output_canonical",
    "external_audit_accepted",
    "off_path_unchanged",
)
REQUIRED_ARTIFACTS = {
    "source",
    "binary",
    "python",
    "build_receipt",
    "dependency_inventory",
    "prebuilt_bundle",
    "prebuilt_preparation",
    "python_runtime_inventory",
    "design_note",
    "hash_contract",
    "audit_contract",
    "submitter",
    "runner",
    "finalizer_sbatch",
    "finalizer",
    "authorizer",
    "authorization_request_executor",
    "control_git",
    "validator",
    "exec_helper",
    "prebuilt_bundle_tool",
    "prebuilt_preparer",
    "launch_manifest",
    "prebuilt_bundle_stdout",
    "prebuilt_bundle_stderr",
    "bundle",
    "audit_receipt",
    "project_stdout",
    "project_stderr",
    "audit_stdout",
    "audit_stderr",
}

RECEIPT_FIELDS = (
    "schema_version",
    "exact_bundle_sha256",
    "source_sha256",
    "baseline_problem_sha256",
    "trace_sha256",
    "lemma_sequence_sha256",
    "materialized_lemmas_sha256",
    "materialized_candidate_sha256",
    "hashes",
    "result",
)

LAUNCH_FIELDS = (
    "schema",
    "solver_revision",
    "solver_source",
    "target",
    "baseline",
    "toolchain",
    "prebuilt_bundle",
    "prebuilt_preparation",
    "control_tools",
    "artifacts",
)

PINNED_ARTIFACT_HASH_FIELDS = {
    "submitter_sha256": "submitter",
    "runner_sha256": "runner",
    "finalizer_sbatch_sha256": "finalizer_sbatch",
    "finalizer_sha256": "finalizer",
    "authorizer_sha256": "authorizer",
    "authorization_request_executor_sha256": "authorization_request_executor",
    "validator_sha256": "validator",
    "exec_helper_sha256": "exec_helper",
    "prebuilt_preparer_sha256": "prebuilt_preparer",
    "prebuilt_bundle_tool_sha256": "prebuilt_bundle_tool",
    "design_note_sha256": "design_note",
    "hash_contract_sha256": "hash_contract",
    "audit_contract_sha256": "audit_contract",
}

MAX_JSON_BYTES = 256 * 1024 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_RUNTIME_FILES = 128
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
REQUIRED_MEMFD_SEALS = (
    getattr(fcntl, "F_SEAL_WRITE", 0x0008)
    | getattr(fcntl, "F_SEAL_GROW", 0x0004)
    | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
    | getattr(fcntl, "F_SEAL_SEAL", 0x0001)
)


class ValidationError(RuntimeError):
    pass


def _fail(message: str) -> None:
    raise ValidationError(message)


def _exact_keys(value: object, expected: Iterable[str], context: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{context} must be an object")
    expected_order = tuple(expected)
    expected_set = set(expected_order)
    actual_set = set(value)
    if actual_set != expected_set:
        missing = sorted(expected_set - actual_set)
        extra = sorted(actual_set - expected_set)
        _fail(f"{context} keys differ: missing={missing}, extra={extra}")
    if tuple(value) != expected_order:
        _fail(f"{context} fields are not in canonical Rust serialization order")
    return value


def _u64(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**64:
        _fail(f"{context} must be a u64")
    return value


def _i32(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not -(2**31) <= value < 2**31:
        _fail(f"{context} must be an i32")
    return value


def _u32(value: object, context: str) -> int:
    value = _u64(value, context)
    if value >= 2**32:
        _fail(f"{context} must be a u32")
    return value


def _boolean(value: object, context: str) -> bool:
    if type(value) is not bool:
        _fail(f"{context} must be a Boolean")
    return value


def _canonical_sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail(f"{context} must be 64 lowercase hexadecimal digits")
    return value


def _no_duplicate_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    _fail(f"non-finite JSON value is forbidden: {value}")


def _read_stable_regular(
    path: Path,
    *,
    maximum_bytes: int,
    reject_symlink: bool = True,
) -> tuple[bytes, os.stat_result, Path]:
    if not path.is_absolute():
        _fail(f"artifact path must be absolute: {path}")
    proc_match = re.fullmatch(r"/proc/self/fd/([0-9]+)", os.fspath(path))
    inherited_fd = int(proc_match.group(1)) if proc_match is not None else None
    if inherited_fd is None:
        try:
            initial_lstat = path.lstat()
        except OSError as error:
            _fail(f"cannot inspect artifact {path}: {error}")
        if reject_symlink and stat.S_ISLNK(initial_lstat.st_mode):
            _fail(f"artifact must not be a symbolic link: {path}")
        resolved = path.resolve(strict=True)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if reject_symlink:
            flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(resolved, flags)
        except OSError as error:
            _fail(f"cannot open artifact {resolved}: {error}")
    else:
        resolved = path
        try:
            descriptor = os.dup(inherited_fd)
            os.set_inheritable(descriptor, False)
        except OSError as error:
            _fail(f"cannot duplicate inherited artifact descriptor {path}: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail(f"artifact is not a regular file: {resolved}")
        if before.st_size < 0 or before.st_size > maximum_bytes:
            _fail(f"artifact size is outside the bound: {resolved}")
        chunks: list[bytes] = []
        offset = 0
        remaining = before.st_size
        while remaining:
            chunk = os.pread(descriptor, min(1024 * 1024, remaining), offset)
            if not chunk:
                _fail(f"artifact was truncated while reading: {resolved}")
            chunks.append(chunk)
            offset += len(chunk)
            remaining -= len(chunk)
        if os.pread(descriptor, 1, offset):
            _fail(f"artifact grew while reading: {resolved}")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        named = os.fstat(inherited_fd) if inherited_fd is not None else resolved.stat()
    except OSError as error:
        _fail(f"cannot re-inspect artifact {resolved}: {error}")
    identity = lambda item: (item.st_dev, item.st_ino)
    stable_fields = lambda item: (item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if identity(before) != identity(after) or identity(before) != identity(named):
        _fail(f"artifact identity changed while reading: {resolved}")
    if stable_fields(before) != stable_fields(after) or stable_fields(before) != stable_fields(named):
        _fail(f"artifact metadata changed while reading: {resolved}")
    return b"".join(chunks), before, resolved


def _load_exact_json(path: Path) -> tuple[dict[str, Any], bytes, os.stat_result, Path]:
    data, metadata, resolved = _read_stable_regular(
        path, maximum_bytes=MAX_JSON_BYTES
    )
    if not data.endswith(b"\n") or data.endswith(b"\n\n") or b"\n" in data[:-1]:
        _fail(f"JSON artifact must be one record with one terminal newline: {resolved}")
    try:
        body = data[:-1].decode("ascii")
    except UnicodeDecodeError:
        _fail(f"JSON artifact is not ASCII: {resolved}")
    try:
        value = json.loads(
            body,
            object_pairs_hook=_no_duplicate_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValidationError) as error:
        _fail(f"cannot decode exact JSON artifact {resolved}: {error}")
    if not isinstance(value, dict):
        _fail(f"JSON artifact root must be an object: {resolved}")
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    if encoded != body:
        _fail(f"JSON artifact is not compact canonical JSON: {resolved}")
    return value, data, metadata, resolved


def _validate_prebuilt_build_receipt(
    value: object,
    solver_source: Mapping[str, Any],
    prebuilt_bundle: Mapping[str, Any],
) -> dict[str, Any]:
    receipt = dict(
        _exact_keys(
            value,
            (
                "binary_dependencies_sha256",
                "build_command",
                "candidate_bytes",
                "candidate_sha256",
                "cargo_lock_sha256",
                "cargo_toml_sha256",
                "features",
                "profile",
                "rust_target",
                "schema",
                "source_commit",
                "source_tree",
            ),
            "prebuilt build receipt",
        )
    )
    for field in (
        "binary_dependencies_sha256",
        "candidate_sha256",
        "cargo_lock_sha256",
        "cargo_toml_sha256",
    ):
        receipt[field] = _canonical_sha256(
            receipt[field], f"prebuilt build receipt.{field}"
        )
    receipt["candidate_bytes"] = _u64(
        receipt["candidate_bytes"], "prebuilt build receipt.candidate_bytes"
    )
    for field in ("source_commit", "source_tree"):
        if (
            not isinstance(receipt[field], str)
            or REVISION_RE.fullmatch(receipt[field]) is None
        ):
            _fail(f"prebuilt build receipt.{field} is not a canonical Git identity")
    exact_values = {
        "schema": BUILD_RECEIPT_SCHEMA,
        "source_commit": solver_source["commit"],
        "source_tree": solver_source["tree"],
        "candidate_sha256": prebuilt_bundle["candidate_sha256"],
        "candidate_bytes": prebuilt_bundle["candidate_bytes"],
        "binary_dependencies_sha256": prebuilt_bundle[
            "dependency_inventory_sha256"
        ],
        "build_command": PREBUILT_BUILD_COMMAND,
        "features": ["certificates"],
        "profile": "release",
        "rust_target": "x86_64-unknown-linux-gnu",
    }
    for field, expected in exact_values.items():
        if receipt[field] != expected:
            _fail(f"prebuilt build receipt.{field} differs from the launch contract")
    return receipt


def _validate_binary_dependency_inventory(
    value: object, candidate_sha256: str
) -> dict[str, Any]:
    inventory = dict(
        _exact_keys(
            value,
            ("candidate_sha256", "platform", "runtime_files", "schema"),
            "binary dependency inventory",
        )
    )
    if inventory["schema"] != DEPENDENCY_INVENTORY_SCHEMA:
        _fail("binary dependency inventory schema differs")
    if inventory["platform"] != "linux-x86_64":
        _fail("binary dependency inventory platform differs")
    if (
        _canonical_sha256(
            inventory["candidate_sha256"],
            "binary dependency inventory.candidate_sha256",
        )
        != candidate_sha256
    ):
        _fail("binary dependency inventory candidate SHA-256 differs")
    raw_files = inventory["runtime_files"]
    if not isinstance(raw_files, list):
        _fail("binary dependency inventory.runtime_files must be an array")
    if not 1 <= len(raw_files) <= MAX_RUNTIME_FILES:
        _fail(
            "binary dependency inventory.runtime_files must contain between "
            f"1 and {MAX_RUNTIME_FILES} entries"
        )
    runtime_files: list[dict[str, str]] = []
    for index, raw_record in enumerate(raw_files):
        record = dict(
            _exact_keys(
                raw_record,
                ("path", "sha256"),
                f"binary dependency inventory.runtime_files[{index}]",
            )
        )
        raw_path = record["path"]
        if (
            not isinstance(raw_path, str)
            or not os.path.isabs(raw_path)
            or os.path.normpath(raw_path) != raw_path
            or os.path.realpath(raw_path) != raw_path
            or "\n" in raw_path
            or "\0" in raw_path
        ):
            _fail(
                "binary dependency inventory runtime path must be canonical, "
                "absolute, and nonsymlinked"
            )
        expected_sha256 = _canonical_sha256(
            record["sha256"],
            f"binary dependency inventory.runtime_files[{index}].sha256",
        )
        dependency, _, resolved = _read_stable_regular(
            Path(raw_path), maximum_bytes=MAX_ARTIFACT_BYTES
        )
        if resolved != Path(raw_path):
            _fail("binary dependency inventory runtime path changed while read")
        if hashlib.sha256(dependency).hexdigest() != expected_sha256:
            _fail(f"runtime dependency SHA-256 differs: {raw_path}")
        runtime_files.append({"path": raw_path, "sha256": expected_sha256})
    expected_order = sorted(
        runtime_files, key=lambda record: record["path"].encode("utf-8")
    )
    if runtime_files != expected_order or len(
        {record["path"] for record in runtime_files}
    ) != len(runtime_files):
        _fail("binary dependency inventory runtime files are duplicated or unsorted")
    inventory["runtime_files"] = runtime_files
    return inventory


def _preparation_file_record(value: object, context: str) -> dict[str, Any]:
    record = dict(_exact_keys(value, ("path", "sha256"), context))
    if (
        not isinstance(record["path"], str)
        or not os.path.isabs(record["path"])
        or os.path.normpath(record["path"]) != record["path"]
        or os.path.realpath(record["path"]) != record["path"]
        or "\n" in record["path"]
        or "\0" in record["path"]
    ):
        _fail(f"{context}.path must be canonical, absolute, and nonsymlinked")
    record["sha256"] = _canonical_sha256(
        record["sha256"], f"{context}.sha256"
    )
    return record


def _validate_preparation_elf_record(value: object, context: str) -> dict[str, Any]:
    record = dict(
        _exact_keys(
            value,
            ("interpreter", "needed", "resolved", "runtime_files"),
            context,
        )
    )
    interpreter = record["interpreter"]
    if (
        not isinstance(interpreter, str)
        or not os.path.isabs(interpreter)
        or "\n" in interpreter
        or "\0" in interpreter
    ):
        _fail(f"{context}.interpreter must be one absolute path")
    needed = record["needed"]
    if (
        not isinstance(needed, list)
        or any(
            not isinstance(item, str)
            or not item
            or "/" in item
            or "\n" in item
            or "\0" in item
            for item in needed
        )
        or len(needed) != len(set(needed))
    ):
        _fail(f"{context}.needed must contain unique safe ELF names")
    resolved = record["resolved"]
    if not isinstance(resolved, dict) or any(
        not isinstance(name, str)
        or not name
        or "/" in name
        or "\n" in name
        or "\0" in name
        or not isinstance(path, str)
        or not os.path.isabs(path)
        or os.path.realpath(path) != path
        for name, path in resolved.items()
    ):
        _fail(f"{context}.resolved is malformed")
    if not set(needed).issubset(resolved):
        _fail(f"{context}.resolved must bind every direct DT_NEEDED name")
    record["runtime_files"] = _u64(
        record["runtime_files"], f"{context}.runtime_files"
    )
    if record["runtime_files"] == 0:
        _fail(f"{context}.runtime_files must be positive")
    return record


def _validate_prebuilt_preparation(
    launch_record: object,
    *,
    solver_source: Mapping[str, Any],
    toolchain: Mapping[str, Any],
    prebuilt_bundle: Mapping[str, Any],
    artifact_hashes: Mapping[str, str],
) -> dict[str, Any]:
    launch = dict(
        _exact_keys(
            launch_record,
            ("path", "schema", "sha256"),
            "launch prebuilt_preparation",
        )
    )
    if launch["schema"] != PREBUILT_PREPARATION_SCHEMA:
        _fail("launch prebuilt preparation schema differs")
    preparation_file = _preparation_file_record(
        {"path": launch["path"], "sha256": launch["sha256"]},
        "launch prebuilt_preparation",
    )
    launch.update(preparation_file)
    report, encoded, metadata, resolved_report = _load_exact_json(
        Path(launch["path"])
    )
    if resolved_report != Path(launch["path"]):
        _fail("prebuilt preparation path changed while read")
    if stat.S_IMODE(metadata.st_mode) != 0o400:
        _fail("prebuilt preparation report must be mode 0400")
    if hashlib.sha256(encoded).hexdigest() != launch["sha256"]:
        _fail("prebuilt preparation report SHA-256 differs")
    report = dict(
        _exact_keys(
            report,
            ("artifacts", "build", "elf", "schema", "smoke", "source", "status", "tools"),
            "prebuilt preparation report",
        )
    )
    if (
        report["schema"] != PREBUILT_PREPARATION_SCHEMA
        or report["status"] != "verified"
        or report["source"] != solver_source
    ):
        _fail("prebuilt preparation identity or status differs")

    tools = dict(
        _exact_keys(
            report["tools"],
            ("bundle_tool", "cargo", "preparer", "python", "rustc"),
            "prebuilt preparation tools",
        )
    )
    for label in ("bundle_tool", "preparer"):
        tools[label] = _preparation_file_record(
            tools[label], f"prebuilt preparation tools.{label}"
        )
    for label in ("cargo", "python", "rustc"):
        tool = dict(
            _exact_keys(
                tools[label],
                ("path", "sha256", "version"),
                f"prebuilt preparation tools.{label}",
            )
        )
        base = _preparation_file_record(
            {"path": tool["path"], "sha256": tool["sha256"]},
            f"prebuilt preparation tools.{label}",
        )
        if (
            not isinstance(tool["version"], str)
            or not tool["version"]
            or "\n" in tool["version"]
        ):
            _fail(f"prebuilt preparation tools.{label}.version is malformed")
        tools[label] = {**base, "version": tool["version"]}
    if tools["bundle_tool"]["sha256"] != artifact_hashes["prebuilt_bundle_tool_sha256"]:
        _fail("prebuilt preparation bundle tool differs from the launch artifact")
    if tools["preparer"]["sha256"] != artifact_hashes["prebuilt_preparer_sha256"]:
        _fail("prebuilt preparation producer differs from the launch artifact")
    python = toolchain["python"]
    for field in ("path", "sha256", "version"):
        if tools["python"][field] != python[field]:
            _fail(f"prebuilt preparation Python {field} differs from the launch toolchain")
    for label in ("bundle_tool", "cargo", "preparer", "python", "rustc"):
        payload, _, actual_path = _read_stable_regular(
            Path(tools[label]["path"]), maximum_bytes=MAX_ARTIFACT_BYTES
        )
        if actual_path != Path(tools[label]["path"]):
            _fail(f"prebuilt preparation tool path changed: {label}")
        if hashlib.sha256(payload).hexdigest() != tools[label]["sha256"]:
            _fail(f"prebuilt preparation tool SHA-256 differs: {label}")

    artifacts = dict(
        _exact_keys(
            report["artifacts"],
            (
                "build_a_candidate",
                "build_a_stderr",
                "build_a_stdout",
                "build_b_candidate",
                "build_b_stderr",
                "build_b_stdout",
                "build_receipt",
                "candidate",
                "dependency_inventory",
                "prebuilt_bundle",
                "python_runtime_inventory",
            ),
            "prebuilt preparation artifacts",
        )
    )
    for label in (
        "build_a_stderr",
        "build_a_stdout",
        "build_b_stderr",
        "build_b_stdout",
        "build_receipt",
        "dependency_inventory",
        "python_runtime_inventory",
    ):
        artifacts[label] = _preparation_file_record(
            artifacts[label], f"prebuilt preparation artifacts.{label}"
        )
    for label in ("build_a_candidate", "build_b_candidate"):
        retained = dict(
            _exact_keys(
                artifacts[label],
                ("bytes", "path", "sha256"),
                f"prebuilt preparation artifacts.{label}",
            )
        )
        retained_base = _preparation_file_record(
            {"path": retained["path"], "sha256": retained["sha256"]},
            f"prebuilt preparation artifacts.{label}",
        )
        retained["bytes"] = _u64(
            retained["bytes"], f"prebuilt preparation artifacts.{label}.bytes"
        )
        retained.update(retained_base)
        artifacts[label] = retained
    candidate = dict(
        _exact_keys(
            artifacts["candidate"],
            ("bytes", "path", "sha256"),
            "prebuilt preparation artifacts.candidate",
        )
    )
    candidate_base = _preparation_file_record(
        {"path": candidate["path"], "sha256": candidate["sha256"]},
        "prebuilt preparation artifacts.candidate",
    )
    candidate["bytes"] = _u64(
        candidate["bytes"], "prebuilt preparation artifacts.candidate.bytes"
    )
    candidate.update(candidate_base)
    artifacts["candidate"] = candidate
    bundle_artifact = dict(
        _exact_keys(
            artifacts["prebuilt_bundle"],
            ("manifest_sha256", "path", "sha256"),
            "prebuilt preparation artifacts.prebuilt_bundle",
        )
    )
    bundle_base = _preparation_file_record(
        {"path": bundle_artifact["path"], "sha256": bundle_artifact["sha256"]},
        "prebuilt preparation artifacts.prebuilt_bundle",
    )
    bundle_artifact.update(bundle_base)
    bundle_artifact["manifest_sha256"] = _canonical_sha256(
        bundle_artifact["manifest_sha256"],
        "prebuilt preparation artifacts.prebuilt_bundle.manifest_sha256",
    )
    artifacts["prebuilt_bundle"] = bundle_artifact
    expected_candidate = {
        "bytes": prebuilt_bundle["candidate_bytes"],
        "sha256": prebuilt_bundle["candidate_sha256"],
    }
    for field, expected in expected_candidate.items():
        if candidate[field] != expected:
            _fail(f"prebuilt preparation candidate {field} differs from the launch")
    if (
        bundle_artifact["path"] != prebuilt_bundle["path"]
        or bundle_artifact["sha256"] != prebuilt_bundle["sha256"]
        or bundle_artifact["manifest_sha256"] != prebuilt_bundle["manifest_sha256"]
    ):
        _fail("prebuilt preparation bundle differs from the launch")
    if artifacts["build_receipt"]["sha256"] != prebuilt_bundle["build_receipt_sha256"]:
        _fail("prebuilt preparation receipt differs from the launch")
    if artifacts["dependency_inventory"]["sha256"] != prebuilt_bundle["dependency_inventory_sha256"]:
        _fail("prebuilt preparation dependency inventory differs from the launch")

    candidate_bytes, _, candidate_path = _read_stable_regular(
        Path(candidate["path"]), maximum_bytes=MAX_ARTIFACT_BYTES
    )
    if (
        candidate_path != Path(candidate["path"])
        or len(candidate_bytes) != candidate["bytes"]
        or hashlib.sha256(candidate_bytes).hexdigest() != candidate["sha256"]
        or not candidate_bytes.startswith(b"\x7fELF\x02\x01\x01")
    ):
        _fail("prebuilt preparation candidate bytes or ELF identity differ")
    for label in ("build_a_candidate", "build_b_candidate"):
        retained = artifacts[label]
        retained_bytes, retained_metadata, retained_path = _read_stable_regular(
            Path(retained["path"]), maximum_bytes=MAX_ARTIFACT_BYTES
        )
        if (
            retained_path != Path(retained["path"])
            or stat.S_IMODE(retained_metadata.st_mode) != 0o400
            or len(retained_bytes) != retained["bytes"]
            or hashlib.sha256(retained_bytes).hexdigest() != retained["sha256"]
            or retained_bytes != candidate_bytes
        ):
            _fail(f"prebuilt preparation {label} differs from the published candidate")
    retained_logs: dict[str, bytes] = {}
    for label in (
        "build_a_stderr",
        "build_a_stdout",
        "build_b_stderr",
        "build_b_stdout",
    ):
        log = artifacts[label]
        log_bytes, log_metadata, log_path = _read_stable_regular(
            Path(log["path"]), maximum_bytes=MAX_ARTIFACT_BYTES
        )
        if (
            log_path != Path(log["path"])
            or stat.S_IMODE(log_metadata.st_mode) != 0o400
            or hashlib.sha256(log_bytes).hexdigest() != log["sha256"]
        ):
            _fail(f"prebuilt preparation {label} bytes or mode differ")
        retained_logs[label] = log_bytes
    receipt, receipt_bytes, receipt_metadata, _ = _load_exact_json(
        Path(artifacts["build_receipt"]["path"])
    )
    inventory, inventory_bytes, inventory_metadata, _ = _load_exact_json(
        Path(artifacts["dependency_inventory"]["path"])
    )
    python_inventory, python_inventory_bytes, python_inventory_metadata, _ = _load_exact_json(
        Path(artifacts["python_runtime_inventory"]["path"])
    )
    for label, value, expected, metadata_value in (
        ("build receipt", receipt_bytes, artifacts["build_receipt"]["sha256"], receipt_metadata),
        ("dependency inventory", inventory_bytes, artifacts["dependency_inventory"]["sha256"], inventory_metadata),
        ("Python runtime inventory", python_inventory_bytes, artifacts["python_runtime_inventory"]["sha256"], python_inventory_metadata),
    ):
        if hashlib.sha256(value).hexdigest() != expected or stat.S_IMODE(metadata_value.st_mode) != 0o400:
            _fail(f"prebuilt preparation {label} bytes or mode differ")
    _validate_prebuilt_build_receipt(receipt, solver_source, prebuilt_bundle)
    candidate_inventory = _validate_binary_dependency_inventory(
        inventory, prebuilt_bundle["candidate_sha256"]
    )
    python_inventory = _validate_binary_dependency_inventory(
        python_inventory, python["sha256"]
    )
    if not candidate_inventory["runtime_files"] or not python_inventory["runtime_files"]:
        _fail("prebuilt preparation runtime inventories must be nonempty")

    build = dict(
        _exact_keys(
            report["build"],
            ("command", "first", "reproducible", "second"),
            "prebuilt preparation build",
        )
    )
    if build["command"] != PREBUILT_BUILD_COMMAND or build["reproducible"] is not True:
        _fail("prebuilt preparation did not attest the exact reproducible build")
    for label in ("first", "second"):
        item = dict(
            _exact_keys(
                build[label],
                ("candidate_sha256", "stderr_sha256", "stdout_sha256"),
                f"prebuilt preparation build.{label}",
            )
        )
        for field in item:
            item[field] = _canonical_sha256(
                item[field], f"prebuilt preparation build.{label}.{field}"
            )
        if item["candidate_sha256"] != prebuilt_bundle["candidate_sha256"]:
            _fail(f"prebuilt preparation build.{label} candidate differs")
        build[label] = item
    retained_build_evidence = {
        "first": (
            artifacts["build_a_candidate"]["sha256"],
            artifacts["build_a_stderr"]["sha256"],
            artifacts["build_a_stdout"]["sha256"],
        ),
        "second": (
            artifacts["build_b_candidate"]["sha256"],
            artifacts["build_b_stderr"]["sha256"],
            artifacts["build_b_stdout"]["sha256"],
        ),
    }
    for label, expected in retained_build_evidence.items():
        actual = (
            build[label]["candidate_sha256"],
            build[label]["stderr_sha256"],
            build[label]["stdout_sha256"],
        )
        if actual != expected:
            _fail(f"prebuilt preparation build.{label} differs from retained artifacts")

    elf = dict(
        _exact_keys(
            report["elf"],
            ("candidate", "controller_python"),
            "prebuilt preparation ELF",
        )
    )
    elf["candidate"] = _validate_preparation_elf_record(
        elf["candidate"], "prebuilt preparation ELF.candidate"
    )
    elf["controller_python"] = _validate_preparation_elf_record(
        elf["controller_python"], "prebuilt preparation ELF.controller_python"
    )
    if elf["candidate"]["runtime_files"] != len(candidate_inventory["runtime_files"]):
        _fail("prebuilt preparation candidate runtime count differs")
    if elf["controller_python"]["runtime_files"] != len(python_inventory["runtime_files"]):
        _fail("prebuilt preparation Python runtime count differs")
    for label, inventory_value in (
        ("candidate", candidate_inventory),
        ("controller Python", python_inventory),
    ):
        elf_record = elf[
            "candidate" if label == "candidate" else "controller_python"
        ]
        inventory_paths = {
            item["path"] for item in inventory_value["runtime_files"]
        }
        attested_paths = set(elf_record["resolved"].values())
        attested_paths.add(os.path.realpath(elf_record["interpreter"]))
        if attested_paths != inventory_paths:
            _fail(
                f"prebuilt preparation {label} ELF resolution differs from "
                "its runtime inventory"
            )

    smoke = dict(
        _exact_keys(
            report["smoke"],
            ("help_sha256", "python_sha256", "version", "version_sha256"),
            "prebuilt preparation smoke",
        )
    )
    for field in ("help_sha256", "python_sha256", "version_sha256"):
        smoke[field] = _canonical_sha256(
            smoke[field], f"prebuilt preparation smoke.{field}"
        )
    if (
        not isinstance(smoke["version"], str)
        or re.fullmatch(r"euf-viper [0-9]+\.[0-9]+\.[0-9]+", smoke["version"])
        is None
    ):
        _fail("prebuilt preparation smoke.version is malformed")

    report["artifacts"] = artifacts
    report["build"] = build
    report["elf"] = elf
    report["smoke"] = smoke
    report["tools"] = tools
    launch["python_runtime_inventory_path"] = artifacts[
        "python_runtime_inventory"
    ]["path"]
    launch["python_runtime_inventory_sha256"] = artifacts[
        "python_runtime_inventory"
    ]["sha256"]
    launch["report"] = report
    return launch


def _validate_hash_bindings(value: object, source_sha256: str, context: str) -> dict[str, str]:
    bindings = dict(_exact_keys(value, HASH_FIELDS, context))
    for field in HASH_FIELDS:
        bindings[field] = _canonical_sha256(bindings[field], f"{context}.{field}")
    for field in INTERNAL_HASH_FIELDS:
        if bindings[field] == ZERO_SHA256:
            _fail(f"{context}.{field} must be nonzero")
    for field in EXTERNAL_HASH_FIELDS:
        if bindings[field] != ZERO_SHA256:
            _fail(f"{context}.{field} must remain zero in Stage 0A projection")
    expected = {
        "source_sha256": source_sha256,
        "root_cnf_mode_sha256": ROOT_CNF_MODE_SHA256,
        "atom_map_sha256": ATOM_MAP_SHA256,
        "baseline_cnf_sha256": BASELINE_CNF_SHA256,
        "baseline_problem_sha256": BASELINE_PROBLEM_SHA256,
    }
    for field, digest in expected.items():
        if bindings[field] != digest:
            _fail(f"{context}.{field} differs from the frozen identity")
    if bindings["lemma_sequence_sha256"] != bindings["materialized_lemmas_sha256"]:
        _fail(f"{context} lemma and materialized-lemma hashes differ")
    return bindings


def _validate_rule_counters(value: object, context: str) -> dict[str, int]:
    counters = dict(_exact_keys(value, RULE_COUNTER_FIELDS, context))
    for field in RULE_COUNTER_FIELDS:
        counters[field] = _u64(counters[field], f"{context}.{field}")
    return counters


def _validate_selector(value: object, context: str) -> dict[str, Any]:
    selector = dict(_exact_keys(value, ("mode", "facts", "decision"), context))
    if selector["mode"] != "clique-er-auto":
        _fail(f"{context}.mode is not clique-er-auto")
    facts = dict(
        _exact_keys(selector["facts"], EXPECTED_SELECTOR_FACTS, f"{context}.facts")
    )
    for field, expected in EXPECTED_SELECTOR_FACTS.items():
        actual = facts[field]
        if isinstance(expected, int):
            actual = _u64(actual, f"{context}.facts.{field}")
        elif not isinstance(actual, str):
            _fail(f"{context}.facts.{field} must be text")
        if actual != expected:
            _fail(f"{context}.facts.{field} differs from the frozen target")
        facts[field] = actual
    decision = dict(
        _exact_keys(selector["decision"], ("decision",), f"{context}.decision")
    )
    if decision["decision"] != "selected":
        _fail(f"{context} did not select the frozen target")
    selector["facts"] = facts
    selector["decision"] = decision
    return selector


def _validate_counters(value: object) -> dict[str, Any]:
    counters = dict(_exact_keys(value, ("input", "search", "pruning", "output"), "counters"))
    inputs = dict(_exact_keys(counters["input"], INPUT_COUNTER_FIELDS, "counters.input"))
    for field in INPUT_COUNTER_FIELDS:
        inputs[field] = _u64(inputs[field], f"counters.input.{field}")
    for field, expected in EXPECTED_INPUT_COUNTERS.items():
        if inputs[field] != expected:
            _fail(f"counters.input.{field} differs from the frozen baseline")

    search = dict(_exact_keys(counters["search"], SEARCH_COUNTER_FIELDS, "counters.search"))
    search["attempted_events"] = _validate_rule_counters(
        search["attempted_events"], "counters.search.attempted_events"
    )
    search["accepted_events"] = _validate_rule_counters(
        search["accepted_events"], "counters.search.accepted_events"
    )
    for field in SEARCH_COUNTER_FIELDS[2:]:
        search[field] = _u64(search[field], f"counters.search.{field}")

    for field, limit in SEARCH_LIMITS.items():
        if search[field] > limit:
            _fail(f"counters.search.{field} exceeds the frozen limit {limit}")
    if search["canonical_proof_work_literal_charge"] < inputs["baseline_literal_slots"]:
        _fail("canonical proof-work charge is below its frozen baseline initialization")
    if search["live_worklist_entries"] > search["peak_live_worklist_entries"]:
        _fail("live worklist entries exceed the recorded peak")
    if search["retained_antichain_entries"] > search["peak_retained_antichain_entries"]:
        _fail("retained antichain entries exceed the recorded peak")
    if search["distinct_event_keys_inserted"] != search["worklist_pushes"]:
        _fail("distinct event-key and worklist-push counters differ")
    if (
        search["events_popped"] + search["queued_events_discarded_at_theory_empty"]
        != search["worklist_pushes"]
    ):
        _fail("popped and theory-empty-discarded events do not partition worklist pushes")
    if search["live_worklist_entries"] != 0:
        _fail("a completed Stage 0A projection retained live worklist entries")
    accepted_total = sum(search["accepted_events"].values())
    attempted_total = sum(search["attempted_events"].values())
    if attempted_total < search["worklist_pushes"]:
        _fail("attempted rule counters are below distinct worklist pushes")
    if any(
        search["accepted_events"][field] > search["attempted_events"][field]
        for field in RULE_COUNTER_FIELDS
    ):
        _fail("accepted rule counters exceed attempted rule counters")
    if accepted_total != (
        search["accepted_equality_nodes"] + search["accepted_conflict_clauses"]
    ):
        _fail("accepted rule counters do not partition accepted trace records")

    expected_memory = sum(
        search[field] * weight for field, weight in MEMORY_WEIGHTS.items()
    )
    expected_memory += inputs["application_pairs"] * 32
    expected_memory += inputs["application_argument_slots"] * 4
    if search["logical_incremental_memory_bytes"] != expected_memory:
        _fail("logical incremental memory differs from the frozen accounting equation")

    pruning = dict(
        _exact_keys(counters["pruning"], PRUNING_COUNTER_FIELDS, "counters.pruning")
    )
    for field in PRUNING_COUNTER_FIELDS:
        pruning[field] = _u64(pruning[field], f"counters.pruning.{field}")

    output = dict(_exact_keys(counters["output"], OUTPUT_COUNTER_FIELDS, "counters.output"))
    for field in OUTPUT_COUNTER_FIELDS:
        output[field] = _u64(output[field], f"counters.output.{field}")
    if not 1 <= output["emitted_lemmas"] <= 8_192:
        _fail("Stage 0A requires between 1 and 8192 emitted lemmas")
    if output["emitted_literal_slots"] > 65_536:
        _fail("Stage 0A emitted-literal cap exceeded")
    if output["emitted_p95_width"] > 8 or output["emitted_maximum_width"] > 32:
        _fail("Stage 0A emitted-width gate failed")
    if output["emitted_with_missing_equality_congruence"] == 0:
        _fail("Stage 0A lacks missing-equality Congruence evidence")
    if output["emitted_with_missing_equality_congruence"] > output["emitted_lemmas"]:
        _fail("missing-equality Congruence count exceeds emitted lemmas")
    counters["input"] = inputs
    counters["search"] = search
    counters["pruning"] = pruning
    counters["output"] = output
    return counters


def _validate_clause(value: object, context: str) -> list[int]:
    if not isinstance(value, list):
        _fail(f"{context} must be a literal array")
    clause = [_i32(literal, f"{context}[{index}]") for index, literal in enumerate(value)]
    if any(literal == 0 for literal in clause):
        _fail(f"{context} contains zero")
    if any(left >= right for left, right in zip(clause, clause[1:])):
        _fail(f"{context} is not strictly sorted")
    seen = set(clause)
    if any(-literal in seen for literal in clause):
        _fail(f"{context} is tautological")
    return clause


def _extract_output(
    status: object,
) -> tuple[str, list[list[int]], list[int], int | None]:
    status_record = _exact_keys(status, ("status", "detail"), "compiler.status")
    if status_record["status"] != "completed":
        _fail("compiler did not complete")
    detail = _exact_keys(
        status_record["detail"], ("outcome", "output"), "compiler.status.detail"
    )
    outcome = detail["outcome"]
    output = detail["output"]
    if outcome == "lemmas":
        if not isinstance(output, list) or not output:
            _fail("lemma outcome must contain a nonempty lemma sequence")
        clauses: list[list[int]] = []
        source_clause_ids: list[int] = []
        for index, lemma_value in enumerate(output):
            lemma = _exact_keys(
                lemma_value, ("source_clause_id", "clause"), f"compiler.lemma[{index}]"
            )
            source_clause_ids.append(
                _u32(
                    lemma["source_clause_id"],
                    f"compiler.lemma[{index}].source_clause_id",
                )
            )
            clause = _validate_clause(lemma["clause"], f"compiler.lemma[{index}].clause")
            if not clause:
                _fail("ordinary emitted lemmas must be nonempty")
            clauses.append(clause)
        if any(
            (len(left), left) >= (len(right), right)
            for left, right in zip(clauses, clauses[1:])
        ):
            _fail("ordinary emitted lemmas are not in canonical output order")
        return outcome, clauses, source_clause_ids, None
    if outcome == "theory_empty":
        record = _exact_keys(output, ("terminal_event_id", "lemma"), "compiler.theory_empty")
        terminal_event_id = _u32(
            record["terminal_event_id"], "compiler.theory_empty.terminal_event_id"
        )
        lemma = _exact_keys(
            record["lemma"], ("source_clause_id", "clause"), "compiler.theory_empty.lemma"
        )
        source_clause_id = _u32(
            lemma["source_clause_id"], "compiler.theory_empty.lemma.source_clause_id"
        )
        clause = _validate_clause(lemma["clause"], "compiler.theory_empty.lemma.clause")
        if clause:
            _fail("theory-empty output must contain exactly one empty clause")
        return outcome, [clause], [source_clause_id], terminal_event_id
    _fail("Stage 0A output must be lemmas or theory_empty")
    raise AssertionError("unreachable")


def _be_u8(value: int) -> bytes:
    return value.to_bytes(1, "big")


def _be_u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _be_i32(value: int) -> bytes:
    return value.to_bytes(4, "big", signed=True)


def _be_u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _encoded_clause(clause: Sequence[int]) -> bytes:
    return _be_u64(len(clause)) + b"".join(_be_i32(literal) for literal in clause)


def _encoded_pivot(value: object, context: str, prior_derived_widths: Mapping[int, int], baseline_clauses: int) -> bytes:
    pivot = _exact_keys(value, ("clause", "literal_offset"), context)
    reference = _exact_keys(pivot["clause"], ("id", "origin"), f"{context}.clause")
    clause_id = _u32(reference["id"], f"{context}.clause.id")
    origin = reference["origin"]
    if origin == "baseline":
        if clause_id >= baseline_clauses:
            _fail(f"{context} baseline clause ID is outside the baseline")
        origin_tag = 0
    elif origin == "derived":
        if clause_id not in prior_derived_widths:
            _fail(f"{context} derived clause is not topologically prior")
        origin_tag = 1
    else:
        _fail(f"{context}.clause.origin is invalid")
    offset = _u32(pivot["literal_offset"], f"{context}.literal_offset")
    if origin == "derived" and offset >= prior_derived_widths[clause_id]:
        _fail(f"{context} literal offset is outside the derived clause")
    return _be_u32(clause_id) + _be_u8(origin_tag) + _be_u32(offset)


def _validate_trace(
    trace: object,
    output_count: int,
    counters: Mapping[str, Any],
) -> tuple[dict[str, int], dict[str, int], str, list[dict[str, Any]]]:
    if not isinstance(trace, list):
        _fail("compiler.trace must be an array")
    rules = {field: 0 for field in RULE_COUNTER_FIELDS}
    equality_nodes = 0
    conflict_clauses = 0
    parent_references = 0
    maximum_depth = 0
    literal_slots = 0
    previous_event_id: int | None = None
    derived_widths: dict[int, int] = {}
    conflicts: list[dict[str, Any]] = []
    encoded = bytearray(b"euf-viper-t11-trace-v1\0")
    encoded.extend(_be_u64(len(trace)))
    term_count = counters["input"]["terms"]
    baseline_clauses = counters["input"]["baseline_clauses"]
    events_popped = counters["search"]["events_popped"]
    for index, value in enumerate(trace):
        tagged = _exact_keys(value, ("record_kind", "record"), f"compiler.trace[{index}]")
        kind = tagged["record_kind"]
        record = tagged["record"]
        if not isinstance(record, dict):
            _fail(f"compiler.trace[{index}].record must be an object")
        if kind == "equality":
            record = _exact_keys(
                record,
                ("event_id", "node_id", "depth", "conclusion", "side_clause", "rule"),
                f"compiler.trace[{index}].record",
            )
            event_id = _u32(record["event_id"], f"compiler.trace[{index}].event_id")
            node_id = _u32(record["node_id"], f"compiler.trace[{index}].node_id")
            depth = _u32(record["depth"], f"compiler.trace[{index}].depth")
            if node_id != equality_nodes:
                _fail(f"compiler.trace[{index}] node ID is not sequential")
            conclusion = _exact_keys(
                record["conclusion"], ("left", "right"), f"compiler.trace[{index}].conclusion"
            )
            left = _u64(conclusion["left"], f"compiler.trace[{index}].conclusion.left")
            right = _u64(conclusion["right"], f"compiler.trace[{index}].conclusion.right")
            if left > right or right >= term_count:
                _fail(f"compiler.trace[{index}] equality endpoints are invalid")
            clause = _validate_clause(record["side_clause"], f"compiler.trace[{index}].side_clause")
            rule = _exact_keys(record["rule"], ("rule", "premises"), f"compiler.trace[{index}].rule")
            rule_name = rule["rule"]
            premises = rule["premises"]
            rule_tag: int
            premise_bytes: bytes
            if rule_name == "seed":
                premise = _exact_keys(premises, ("positive_source",), f"compiler.trace[{index}].seed")
                premise_bytes = _encoded_pivot(
                    premise["positive_source"],
                    f"compiler.trace[{index}].seed.positive_source",
                    derived_widths,
                    baseline_clauses,
                )
                rule_tag = 0
            elif rule_name == "reflexivity":
                premise = _exact_keys(premises, ("term",), f"compiler.trace[{index}].reflexivity")
                term = _u64(premise["term"], f"compiler.trace[{index}].reflexivity.term")
                if term >= term_count:
                    _fail(f"compiler.trace[{index}] reflexivity term is outside the term DAG")
                premise_bytes = _be_u64(term)
                rule_tag = 1
            elif rule_name == "transitivity":
                premise = _exact_keys(
                    premises, ("parents", "intermediate"), f"compiler.trace[{index}].transitivity"
                )
                parents = premise["parents"]
                if not isinstance(parents, list) or len(parents) != 2:
                    _fail(f"compiler.trace[{index}] transitivity parents must have length two")
                parent_ids = [
                    _u32(parent, f"compiler.trace[{index}].transitivity.parents[{position}]")
                    for position, parent in enumerate(parents)
                ]
                if parent_ids[0] > parent_ids[1] or any(parent >= node_id for parent in parent_ids):
                    _fail(f"compiler.trace[{index}] transitivity parents are not topological")
                intermediate = _u64(
                    premise["intermediate"], f"compiler.trace[{index}].transitivity.intermediate"
                )
                if intermediate >= term_count:
                    _fail(f"compiler.trace[{index}] transitivity term is outside the term DAG")
                premise_bytes = _be_u32(parent_ids[0]) + _be_u32(parent_ids[1]) + _be_u64(intermediate)
                parent_references += 2
                rule_tag = 2
            elif rule_name == "congruence":
                premise = _exact_keys(
                    premises, ("applications", "arguments"), f"compiler.trace[{index}].congruence"
                )
                applications = premise["applications"]
                if not isinstance(applications, list) or len(applications) != 2:
                    _fail(f"compiler.trace[{index}] congruence applications must have length two")
                application_ids = [
                    _u64(application, f"compiler.trace[{index}].congruence.applications[{position}]")
                    for position, application in enumerate(applications)
                ]
                if application_ids[0] >= application_ids[1] or application_ids[1] >= term_count:
                    _fail(f"compiler.trace[{index}] congruence applications are not canonical")
                arguments = premise["arguments"]
                if not isinstance(arguments, list):
                    _fail(f"compiler.trace[{index}] congruence arguments must be an array")
                argument_bytes = bytearray()
                previous_argument: int | None = None
                for position, argument_value in enumerate(arguments):
                    argument = _exact_keys(
                        argument_value,
                        ("argument_index", "parent"),
                        f"compiler.trace[{index}].congruence.arguments[{position}]",
                    )
                    argument_index = _u32(
                        argument["argument_index"],
                        f"compiler.trace[{index}].congruence.arguments[{position}].argument_index",
                    )
                    parent = _u32(
                        argument["parent"],
                        f"compiler.trace[{index}].congruence.arguments[{position}].parent",
                    )
                    if previous_argument is not None and previous_argument >= argument_index:
                        _fail(f"compiler.trace[{index}] congruence arguments are not ordered")
                    if argument_index >= counters["input"]["maximum_arity"] or parent >= node_id:
                        _fail(f"compiler.trace[{index}] congruence association is not topological")
                    previous_argument = argument_index
                    argument_bytes.extend(_be_u32(argument_index))
                    argument_bytes.extend(_be_u32(parent))
                premise_bytes = (
                    _be_u64(application_ids[0])
                    + _be_u64(application_ids[1])
                    + _be_u64(len(arguments))
                    + bytes(argument_bytes)
                )
                parent_references += len(arguments)
                rule_tag = 3
            else:
                _fail(f"compiler.trace[{index}] has an invalid equality rule")
            equality_nodes += 1
            rules[rule_name] += 1
            encoded.extend(_be_u8(1))
            encoded.extend(_be_u32(event_id))
            encoded.extend(_be_u32(node_id))
            encoded.extend(_be_u32(depth))
            encoded.extend(_be_u64(left))
            encoded.extend(_be_u64(right))
            encoded.extend(_encoded_clause(clause))
            encoded.extend(_be_u8(rule_tag))
            encoded.extend(premise_bytes)
        elif kind == "conflict":
            record = _exact_keys(
                record,
                ("event_id", "clause_id", "depth", "clause", "rule"),
                f"compiler.trace[{index}].record",
            )
            event_id = _u32(record["event_id"], f"compiler.trace[{index}].event_id")
            clause_id = _u32(record["clause_id"], f"compiler.trace[{index}].clause_id")
            depth = _u32(record["depth"], f"compiler.trace[{index}].depth")
            expected_clause_id = baseline_clauses + conflict_clauses
            if clause_id != expected_clause_id:
                _fail(f"compiler.trace[{index}] derived clause ID is not sequential")
            clause = _validate_clause(record["clause"], f"compiler.trace[{index}].clause")
            rule = _exact_keys(
                record["rule"], ("equality_parent", "negative_source"), f"compiler.trace[{index}].rule"
            )
            equality_parent = _u32(
                rule["equality_parent"], f"compiler.trace[{index}].rule.equality_parent"
            )
            if equality_parent >= equality_nodes:
                _fail(f"compiler.trace[{index}] conflict parent is not topological")
            negative_source = _encoded_pivot(
                rule["negative_source"],
                f"compiler.trace[{index}].rule.negative_source",
                derived_widths,
                baseline_clauses,
            )
            derived_widths[clause_id] = len(clause)
            conflicts.append(
                {"event_id": event_id, "clause_id": clause_id, "clause": clause}
            )
            conflict_clauses += 1
            rules["conflict"] += 1
            parent_references += 1
            encoded.extend(_be_u8(2))
            encoded.extend(_be_u32(event_id))
            encoded.extend(_be_u32(clause_id))
            encoded.extend(_be_u32(depth))
            encoded.extend(_encoded_clause(clause))
            encoded.extend(_be_u8(4))
            encoded.extend(_be_u32(equality_parent))
            encoded.extend(negative_source)
        else:
            _fail(f"compiler.trace[{index}] has an invalid record_kind")
        if previous_event_id is not None and previous_event_id >= event_id:
            _fail(f"compiler.trace[{index}] event IDs are not increasing")
        if event_id >= events_popped:
            _fail(f"compiler.trace[{index}] event ID exceeds events_popped")
        previous_event_id = event_id
        maximum_depth = max(maximum_depth, depth)
        literal_slots += len(clause)
    checker = {
        "replayed_equality_nodes": equality_nodes,
        "replayed_conflict_clauses": conflict_clauses,
        "replayed_emitted_lemmas": output_count,
        "replay_failures": 0,
    }
    search = counters["search"]
    structural_counts = {
        "proof_parent_references": parent_references,
        "maximum_proof_depth": maximum_depth,
        "accepted_trace_literal_slots": literal_slots,
    }
    for field, expected in structural_counts.items():
        if search[field] != expected:
            _fail(f"counters.search.{field} does not match the sealed trace")
    return rules, checker, hashlib.sha256(encoded).hexdigest(), conflicts


def _emitted_clause_digest(clauses: Sequence[Sequence[int]]) -> str:
    encoded = bytearray(b"euf-viper-t11-lemma-clause-sequence-v1\0")
    encoded.extend(_be_u64(len(clauses)))
    for clause in clauses:
        encoded.extend(_encoded_clause(clause))
    return hashlib.sha256(encoded).hexdigest()


def _validate_checker_counters(value: object, context: str) -> dict[str, int]:
    counters = dict(_exact_keys(value, CHECKER_COUNTER_FIELDS, context))
    for field in CHECKER_COUNTER_FIELDS:
        counters[field] = _u64(counters[field], f"{context}.{field}")
    if counters["replay_failures"] != 0:
        _fail(f"{context}.replay_failures must be zero")
    return counters


def validate_evidence(
    *,
    source_path: Path,
    bundle_path: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    source, source_stat, source_resolved = _read_stable_regular(
        source_path, maximum_bytes=MAX_ARTIFACT_BYTES
    )
    source_sha256 = hashlib.sha256(source).hexdigest()
    if source_sha256 != TARGET_SHA256:
        _fail("source SHA-256 differs from the frozen T11 target")

    bundle, bundle_bytes, bundle_stat, bundle_resolved = _load_exact_json(bundle_path)
    receipt, receipt_bytes, receipt_stat, receipt_resolved = _load_exact_json(receipt_path)
    identities = {
        (source_stat.st_dev, source_stat.st_ino),
        (bundle_stat.st_dev, bundle_stat.st_ino),
        (receipt_stat.st_dev, receipt_stat.st_ino),
    }
    if len(identities) != 3:
        _fail("source, bundle, and receipt must have distinct file identities")
    if stat.S_IMODE(bundle_stat.st_mode) != 0o400 or stat.S_IMODE(receipt_stat.st_mode) != 0o400:
        _fail("bundle and receipt must be immutable mode 0400")

    bundle_record = _exact_keys(
        bundle,
        ("selector", "compiler", "materialized_lemmas", "checker", "report"),
        "bundle",
    )
    selector = _validate_selector(bundle_record["selector"], "selector")

    compiler = _exact_keys(
        bundle_record["compiler"], ("variant", "status", "trace", "counters", "hashes"), "compiler"
    )
    if compiler["variant"] != "ordinary":
        _fail("Stage 0A requires the ordinary compiler variant")
    outcome, output_clauses, output_source_ids, terminal_event_id = _extract_output(
        compiler["status"]
    )
    counters = _validate_counters(compiler["counters"])
    hashes = _validate_hash_bindings(compiler["hashes"], source_sha256, "compiler.hashes")
    trace_rules, expected_checker_counters, trace_sha256, conflicts = _validate_trace(
        compiler["trace"], len(output_clauses), counters
    )
    if trace_sha256 != hashes["trace_sha256"]:
        _fail("independently recomputed trace hash differs from compiler.hashes")
    if counters["search"]["accepted_events"] != trace_rules:
        _fail("accepted rule counters do not match the sealed trace")
    if counters["search"]["accepted_equality_nodes"] != expected_checker_counters[
        "replayed_equality_nodes"
    ]:
        _fail("accepted equality-node count does not match the sealed trace")
    if counters["search"]["accepted_conflict_clauses"] != expected_checker_counters[
        "replayed_conflict_clauses"
    ]:
        _fail("accepted conflict count does not match the sealed trace")
    if counters["output"]["emitted_lemmas"] != len(output_clauses):
        _fail("emitted lemma count does not match compiler output")
    literal_slots = sum(map(len, output_clauses))
    if counters["output"]["emitted_literal_slots"] != literal_slots:
        _fail("emitted literal count does not match compiler output")
    widths = [len(clause) for clause in output_clauses]
    maximum_width = max(widths, default=0)
    percentile_index = ((len(widths) * 95 + 99) // 100 - 1) if widths else None
    p95_width = widths[percentile_index] if percentile_index is not None else 0
    if counters["output"]["emitted_maximum_width"] != maximum_width:
        _fail("emitted maximum width does not match compiler output")
    if counters["output"]["emitted_p95_width"] != p95_width:
        _fail("emitted p95 width does not match compiler output")

    conflict_by_id = {record["clause_id"]: record for record in conflicts}
    for index, (source_clause_id, clause) in enumerate(
        zip(output_source_ids, output_clauses)
    ):
        source = conflict_by_id.get(source_clause_id)
        if source is None or source["clause"] != clause:
            _fail(f"compiler output lemma {index} is not bound to its conflict record")
    if outcome == "theory_empty":
        if not conflicts or terminal_event_id != conflicts[-1]["event_id"]:
            _fail("theory-empty terminal event is not the final conflict")

    emitted_digest = _emitted_clause_digest(output_clauses)
    if emitted_digest != hashes["lemma_sequence_sha256"]:
        _fail("independently recomputed lemma-sequence hash differs")

    materialized = _exact_keys(
        bundle_record["materialized_lemmas"], ("end_offsets", "literals"), "materialized_lemmas"
    )
    offsets_value = materialized["end_offsets"]
    literals_value = materialized["literals"]
    if not isinstance(offsets_value, list) or not isinstance(literals_value, list):
        _fail("materialized lemma store must contain arrays")
    offsets = [_u64(value, f"materialized_lemmas.end_offsets[{index}]") for index, value in enumerate(offsets_value)]
    literals = [_i32(value, f"materialized_lemmas.literals[{index}]") for index, value in enumerate(literals_value)]
    expected_offsets = [0]
    expected_literals: list[int] = []
    for clause in output_clauses:
        expected_literals.extend(clause)
        expected_offsets.append(len(expected_literals))
    if offsets != expected_offsets or literals != expected_literals:
        _fail("materialized lemma bytes differ from compiler output")
    if emitted_digest != hashes["materialized_lemmas_sha256"]:
        _fail("independently recomputed materialized-lemma hash differs")

    checker = _exact_keys(
        bundle_record["checker"], ("status", "counters", "recomputed_hashes"), "checker"
    )
    checker_status = _exact_keys(checker["status"], ("status",), "checker.status")
    if checker_status["status"] != "accepted":
        _fail("logical checker did not accept")
    checker_counters = _validate_checker_counters(checker["counters"], "checker.counters")
    if checker_counters != expected_checker_counters:
        _fail("checker counters do not match trace and output")
    checker_hashes = _validate_hash_bindings(
        checker["recomputed_hashes"], source_sha256, "checker.recomputed_hashes"
    )
    if checker_hashes != hashes:
        _fail("compiler and checker hashes differ")

    report = _exact_keys(
        bundle_record["report"],
        (
            "schema_version",
            "selector",
            "compiler_variant",
            "outcome",
            "counters",
            "checker_counters",
            "cap_attempt",
            "forbidden_growth",
            "integrity",
            "sat_calls",
            "hashes",
        ),
        "report",
    )
    if _u64(report["schema_version"], "report.schema_version") != 1:
        _fail("report schema version differs")
    report_selector = _validate_selector(report["selector"], "report.selector")
    if report_selector != selector:
        _fail("report selector binding differs")
    if report["compiler_variant"] != "ordinary" or report["outcome"] != outcome:
        _fail("report compiler variant or outcome differs")
    report_counters = _validate_counters(report["counters"])
    report_checker_counters = _validate_checker_counters(
        report["checker_counters"], "report.checker_counters"
    )
    if report_counters != counters or report_checker_counters != checker_counters:
        _fail("report counters differ from compiler or checker")
    if report["cap_attempt"] is not None:
        _fail("Stage 0A reached a hard cap")
    forbidden = _exact_keys(
        report["forbidden_growth"], FORBIDDEN_GROWTH_FIELDS, "report.forbidden_growth"
    )
    if any(_u64(forbidden[field], f"report.forbidden_growth.{field}") != 0 for field in FORBIDDEN_GROWTH_FIELDS):
        _fail("Stage 0A performed forbidden formula growth")
    integrity = dict(
        _exact_keys(report["integrity"], INTEGRITY_FIELDS, "report.integrity")
    )
    expected_integrity = {
        "baseline_unchanged": True,
        "trace_materialization_equal": True,
        "compiler_checker_agree": True,
        "output_canonical": True,
        "external_audit_accepted": False,
        "off_path_unchanged": False,
    }
    for field in INTEGRITY_FIELDS:
        integrity[field] = _boolean(integrity[field], f"report.integrity.{field}")
    if integrity != expected_integrity:
        _fail("report integrity flags differ from the Stage 0A contract")
    if _u64(report["sat_calls"], "report.sat_calls") != 0:
        _fail("Stage 0A dispatched SAT")
    report_hashes = _validate_hash_bindings(report["hashes"], source_sha256, "report.hashes")
    if report_hashes != hashes:
        _fail("report hashes differ from compiler hashes")

    receipt_record = _exact_keys(receipt, RECEIPT_FIELDS, "receipt")
    if _u64(receipt_record["schema_version"], "receipt.schema_version") != 1:
        _fail("audit receipt schema version differs")
    bundle_sha256 = hashlib.sha256(bundle_bytes).hexdigest()
    if _canonical_sha256(receipt_record["exact_bundle_sha256"], "receipt.exact_bundle_sha256") != bundle_sha256:
        _fail("audit receipt does not bind the exact bundle bytes")
    receipt_hashes = _validate_hash_bindings(receipt_record["hashes"], source_sha256, "receipt.hashes")
    if receipt_hashes != hashes:
        _fail("receipt hashes differ from compiler hashes")
    compatibility_fields = (
        "source_sha256",
        "baseline_problem_sha256",
        "trace_sha256",
        "lemma_sequence_sha256",
        "materialized_lemmas_sha256",
        "materialized_candidate_sha256",
    )
    for field in compatibility_fields:
        digest = _canonical_sha256(receipt_record[field], f"receipt.{field}")
        if digest != hashes[field]:
            _fail(f"receipt.{field} differs from receipt.hashes.{field}")
    result = _exact_keys(
        receipt_record["result"],
        ("status", "counters", "checker_counters", "cap_attempt", "recomputed_hashes"),
        "receipt.result",
    )
    audit_status = _exact_keys(result["status"], ("status",), "receipt.result.status")
    if audit_status["status"] != "accepted":
        _fail("external scheduling auditor did not accept")
    audit_counters = _validate_counters(result["counters"])
    if audit_counters != counters:
        _fail("auditor counters differ from compiler counters")
    audit_checker_counters = _validate_checker_counters(
        result["checker_counters"], "receipt.result.checker_counters"
    )
    if audit_checker_counters != checker_counters:
        _fail("auditor checker counters differ")
    if result["cap_attempt"] is not None:
        _fail("auditor reconstructed a hard cap")
    audit_hashes = _validate_hash_bindings(
        result["recomputed_hashes"], source_sha256, "receipt.result.recomputed_hashes"
    )
    if audit_hashes != hashes:
        _fail("auditor hashes differ from compiler hashes")

    return {
        "source_path": str(source_resolved),
        "source_sha256": source_sha256,
        "source_bytes": len(source),
        "bundle_path": str(bundle_resolved),
        "bundle_sha256": bundle_sha256,
        "bundle_bytes": len(bundle_bytes),
        "receipt_path": str(receipt_resolved),
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "receipt_bytes": len(receipt_bytes),
        "outcome": outcome,
        "counters": counters,
        "checker_counters": checker_counters,
        "hashes": hashes,
    }


def _canonical_original_path(value: str, context: str) -> Path:
    if not value or not os.path.isabs(value) or os.path.normpath(value) != value:
        _fail(f"{context} must be a canonical absolute path")
    if re.fullmatch(r"/proc/self/fd/[0-9]+", value) is not None:
        _fail(f"{context} must name the original artifact, not a proc-fd snapshot")
    return Path(value)


def _sealed_snapshot_path(value: str | Path, context: str) -> Path:
    path = Path(value)
    match = re.fullmatch(r"/proc/self/fd/([0-9]+)", os.fspath(path))
    if match is None or int(match.group(1)) <= 2:
        _fail(f"{context} must be a held nonstandard proc-fd snapshot")
    return path


def _parse_artifacts(
    values: Sequence[Sequence[str]],
) -> dict[str, tuple[Path, Path]]:
    artifacts: dict[str, tuple[Path, Path]] = {}
    for value in values:
        if len(value) != 3:
            _fail("artifact binding must contain NAME ORIGINAL_PATH SNAPSHOT_PATH")
        name, raw_original, raw_snapshot = value
        if not re.fullmatch(r"[a-z][a-z0-9_]*", name) or name in artifacts:
            _fail(f"invalid or duplicate artifact name: {name}")
        artifacts[name] = (
            _canonical_original_path(raw_original, f"artifact {name} original path"),
            _sealed_snapshot_path(raw_snapshot, f"artifact {name} snapshot"),
        )
    if set(artifacts) != REQUIRED_ARTIFACTS:
        _fail(
            "artifact set differs: "
            f"missing={sorted(REQUIRED_ARTIFACTS - set(artifacts))}, "
            f"extra={sorted(set(artifacts) - REQUIRED_ARTIFACTS)}"
        )
    return artifacts


def _artifact_record(path: Path, original_path: Path) -> dict[str, Any]:
    path = _sealed_snapshot_path(path, f"artifact {original_path} snapshot")
    descriptor = int(path.name)
    try:
        seals_before = int(fcntl.fcntl(descriptor, F_GET_SEALS))
    except OSError as error:
        _fail(f"cannot inspect sealed artifact snapshot {original_path}: {error}")
    if seals_before & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS:
        _fail(f"artifact snapshot lacks mandatory write/grow/shrink/final seals: {original_path}")
    if not os.get_inheritable(descriptor):
        _fail(f"artifact snapshot descriptor is not inherited: {original_path}")
    data, metadata, _ = _read_stable_regular(
        path, maximum_bytes=MAX_ARTIFACT_BYTES, reject_symlink=False
    )
    try:
        seals_after = int(fcntl.fcntl(descriptor, F_GET_SEALS))
    except OSError as error:
        _fail(f"cannot re-inspect sealed artifact snapshot {original_path}: {error}")
    if seals_after != seals_before:
        _fail(f"artifact snapshot seals changed while reading: {original_path}")
    if stat.S_IMODE(metadata.st_mode) & 0o222:
        _fail(f"artifact snapshot is writable: {original_path}")
    return {
        "path": str(original_path),
        "bytes": len(data),
        "snapshot_mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "snapshot_seals": f"0x{seals_before:x}",
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _write_immutable_json(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    if not path.is_absolute():
        _fail("metadata output path must be absolute")
    parent = path.parent.resolve(strict=True)
    if path.name in {"", ".", ".."}:
        _fail("metadata output path has no canonical file name")
    if not sys.platform.startswith("linux") or not hasattr(os, "O_TMPFILE"):
        _fail("metadata publication requires Linux O_TMPFILE support")
    encoded = (
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    directory_fd = os.open(parent, directory_flags)
    try:
        parent_before = os.fstat(directory_fd)
        try:
            os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _fail("metadata output path must be fresh")
        flags = os.O_RDWR | os.O_TMPFILE | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(".", flags, 0o600, dir_fd=directory_fd)
        try:
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    _fail("short metadata write")
                offset += written
            os.fsync(descriptor)
            if os.pread(descriptor, len(encoded) + 1, 0) != encoded:
                _fail("metadata descriptor verification failed")
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            staged = os.fstat(descriptor)
            if (
                not stat.S_ISREG(staged.st_mode)
                or staged.st_nlink != 0
                or staged.st_size != len(encoded)
                or stat.S_IMODE(staged.st_mode) != 0o400
            ):
                _fail("metadata staging inode differs from the publication contract")
            proc_path = f"/proc/self/fd/{descriptor}"
            proc_metadata = os.stat(proc_path)
            if (staged.st_dev, staged.st_ino) != (
                proc_metadata.st_dev,
                proc_metadata.st_ino,
            ):
                _fail("metadata proc-fd link does not resolve to the staging inode")
            try:
                os.link(
                    proc_path,
                    path.name,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=True,
                )
            except FileExistsError:
                _fail("metadata output path ceased to be fresh")
            os.close(descriptor)
            descriptor = -1
            os.fsync(directory_fd)

            final_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            final_descriptor = os.open(path.name, final_flags, dir_fd=directory_fd)
            try:
                final = os.fstat(final_descriptor)
                if (
                    not stat.S_ISREG(final.st_mode)
                    or (final.st_dev, final.st_ino) != (staged.st_dev, staged.st_ino)
                    or final.st_nlink != 1
                    or final.st_size != len(encoded)
                    or stat.S_IMODE(final.st_mode) != 0o400
                    or os.pread(final_descriptor, len(encoded) + 1, 0) != encoded
                ):
                    _fail("published metadata differs from the exact staging inode")
                binding = {
                    "artifact": "validation metadata",
                    "bytes": final.st_size,
                    "ctime_ns": final.st_ctime_ns,
                    "device": final.st_dev,
                    "inode": final.st_ino,
                    "links": final.st_nlink,
                    "mode": f"{stat.S_IMODE(final.st_mode):04o}",
                    "mtime_ns": final.st_mtime_ns,
                    "path": os.fspath(path),
                    "schema": "euf-viper.t11-publication-binding.v1",
                    "sha256": hashlib.sha256(encoded).hexdigest(),
                }
            finally:
                os.close(final_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        parent_after = os.fstat(directory_fd)
        if (parent_before.st_dev, parent_before.st_ino) != (
            parent_after.st_dev,
            parent_after.st_ino,
        ):
            _fail("metadata parent identity changed")
    finally:
        os.close(directory_fd)
    return binding


def _tool_record(
    artifact_record: Mapping[str, Any],
    expected_sha256: str,
    version: str,
    label: str,
) -> dict[str, Any]:
    record = dict(artifact_record)
    if record["sha256"] != _canonical_sha256(expected_sha256, f"{label} SHA-256"):
        _fail(f"{label} bytes differ from the pinned SHA-256")
    if not isinstance(version, str) or not version or "\n" in version:
        _fail(f"{label} version is not one exact line")
    record["version"] = version
    return record


def _validate_launch_manifest(
    path: Path, expected_sha256: str
) -> tuple[dict[str, Any], str, Path]:
    manifest, exact_bytes, _, resolved = _load_exact_json(path)
    exact_sha256 = hashlib.sha256(exact_bytes).hexdigest()
    if exact_sha256 != _canonical_sha256(
        expected_sha256, "launch manifest SHA-256"
    ):
        _fail("launch manifest bytes differ from the wrapper-frozen SHA-256")
    record = dict(_exact_keys(manifest, LAUNCH_FIELDS, "launch manifest"))
    if record["schema"] != LAUNCH_SCHEMA:
        _fail("launch manifest schema differs")
    revision = record["solver_revision"]
    if not isinstance(revision, str) or REVISION_RE.fullmatch(revision) is None:
        _fail("launch manifest solver revision is not an exact Git commit")
    solver_source = dict(
        _exact_keys(record["solver_source"], ("commit", "tree"), "launch solver_source")
    )
    for field in ("commit", "tree"):
        if (
            not isinstance(solver_source[field], str)
            or REVISION_RE.fullmatch(solver_source[field]) is None
        ):
            _fail(f"launch solver_source.{field} is not a canonical Git identity")
    if solver_source["commit"] != revision:
        _fail("launch solver source commit differs from solver_revision")

    target = dict(
        _exact_keys(record["target"], ("relative_path", "sha256"), "launch target")
    )
    if target["relative_path"] != TARGET_RELATIVE_PATH:
        _fail("launch target relative path differs from the frozen target")
    if _canonical_sha256(target["sha256"], "launch target SHA-256") != TARGET_SHA256:
        _fail("launch target SHA-256 differs from the frozen target")

    baseline_fields = tuple(EXPECTED_INPUT_COUNTERS) + (
        "atom_map_sha256",
        "baseline_cnf_sha256",
        "baseline_problem_sha256",
    )
    baseline = dict(
        _exact_keys(record["baseline"], baseline_fields, "launch baseline")
    )
    for field, expected in EXPECTED_INPUT_COUNTERS.items():
        if _u64(baseline[field], f"launch baseline.{field}") != expected:
            _fail(f"launch baseline.{field} differs from the frozen baseline")
    frozen_hashes = {
        "atom_map_sha256": ATOM_MAP_SHA256,
        "baseline_cnf_sha256": BASELINE_CNF_SHA256,
        "baseline_problem_sha256": BASELINE_PROBLEM_SHA256,
    }
    for field, expected in frozen_hashes.items():
        if _canonical_sha256(baseline[field], f"launch baseline.{field}") != expected:
            _fail(f"launch baseline.{field} differs from the frozen baseline")

    toolchain = dict(
        _exact_keys(
            record["toolchain"],
            ("python",),
            "launch toolchain",
        )
    )
    python = dict(
        _exact_keys(
            toolchain["python"], ("path", "sha256", "version"), "launch python"
        )
    )
    if (
        not isinstance(python["path"], str)
        or not Path(python["path"]).is_absolute()
        or "\n" in python["path"]
        or "\0" in python["path"]
    ):
        _fail("launch python path must be absolute")
    python["sha256"] = _canonical_sha256(
        python["sha256"], "launch python SHA-256"
    )
    if (
        not isinstance(python["version"], str)
        or not python["version"]
        or "\n" in python["version"]
    ):
        _fail("launch python version must be one nonempty line")
    toolchain["python"] = python

    prebuilt_bundle = dict(
        _exact_keys(
            record["prebuilt_bundle"],
            (
                "build_receipt_sha256",
                "candidate_bytes",
                "candidate_sha256",
                "dependency_inventory_sha256",
                "manifest_sha256",
                "path",
                "schema",
                "sha256",
                "source_commit",
                "source_tree",
            ),
            "launch prebuilt_bundle",
        )
    )
    if (
        not isinstance(prebuilt_bundle["path"], str)
        or not Path(prebuilt_bundle["path"]).is_absolute()
        or "\n" in prebuilt_bundle["path"]
        or "\0" in prebuilt_bundle["path"]
    ):
        _fail("launch prebuilt_bundle.path must be absolute")
    if prebuilt_bundle["schema"] != PREBUILT_BUNDLE_SCHEMA:
        _fail("launch prebuilt bundle schema differs")
    for field in (
        "sha256",
        "manifest_sha256",
        "candidate_sha256",
        "build_receipt_sha256",
        "dependency_inventory_sha256",
    ):
        prebuilt_bundle[field] = _canonical_sha256(
            prebuilt_bundle[field], f"launch prebuilt_bundle.{field}"
        )
    _u64(prebuilt_bundle["candidate_bytes"], "launch prebuilt_bundle.candidate_bytes")
    if prebuilt_bundle["candidate_bytes"] == 0:
        _fail("launch prebuilt bundle candidate must be nonempty")
    if (
        prebuilt_bundle["source_commit"] != solver_source["commit"]
        or prebuilt_bundle["source_tree"] != solver_source["tree"]
    ):
        _fail("launch prebuilt bundle source identity differs from solver_source")

    control_tools = dict(
        _exact_keys(
            record["control_tools"],
            ("git", "sbatch", "scontrol", "scancel", "sacct"),
            "launch control_tools",
        )
    )
    for label in ("git", "sbatch", "scontrol", "scancel", "sacct"):
        tool = dict(
            _exact_keys(
                control_tools[label],
                ("path", "sha256", "version"),
                f"launch control_tools.{label}",
            )
        )
        if (
            not isinstance(tool["path"], str)
            or not Path(tool["path"]).is_absolute()
            or "\n" in tool["path"]
            or "\0" in tool["path"]
        ):
            _fail(f"launch control_tools.{label}.path must be absolute")
        tool["sha256"] = _canonical_sha256(
            tool["sha256"], f"launch control_tools.{label}.sha256"
        )
        if (
            not isinstance(tool["version"], str)
            or not tool["version"]
            or "\n" in tool["version"]
        ):
            _fail(f"launch control_tools.{label}.version must be one nonempty line")
        control_tools[label] = tool

    artifacts = dict(
        _exact_keys(
            record["artifacts"],
            PINNED_ARTIFACT_HASH_FIELDS,
            "launch artifacts",
        )
    )
    for field in PINNED_ARTIFACT_HASH_FIELDS:
        artifacts[field] = _canonical_sha256(
            artifacts[field], f"launch artifacts.{field}"
        )
    prebuilt_preparation = _validate_prebuilt_preparation(
        record["prebuilt_preparation"],
        solver_source=solver_source,
        toolchain=toolchain,
        prebuilt_bundle=prebuilt_bundle,
        artifact_hashes=artifacts,
    )
    record["solver_source"] = solver_source
    record["target"] = target
    record["baseline"] = baseline
    record["toolchain"] = toolchain
    record["prebuilt_bundle"] = prebuilt_bundle
    record["prebuilt_preparation"] = prebuilt_preparation
    record["control_tools"] = control_tools
    record["artifacts"] = artifacts
    return record, exact_sha256, resolved


def inspect_launch_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Inspect one frozen T11 launch manifest")
    parser.add_argument("--launch-manifest", type=Path, required=True)
    parser.add_argument("--launch-manifest-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        launch, _, _ = _validate_launch_manifest(
            args.launch_manifest, args.launch_manifest_sha256
        )
        toolchain = launch["toolchain"]
        values = [
            launch["solver_revision"],
            launch["solver_source"]["tree"],
            toolchain["python"]["path"],
            toolchain["python"]["sha256"],
            toolchain["python"]["version"],
        ]
        for field in PINNED_ARTIFACT_HASH_FIELDS:
            values.append(launch["artifacts"][field])
        prebuilt = launch["prebuilt_bundle"]
        values.extend(
            (
                prebuilt["path"],
                prebuilt["sha256"],
                prebuilt["manifest_sha256"],
                prebuilt["schema"],
                prebuilt["source_commit"],
                prebuilt["source_tree"],
                prebuilt["candidate_sha256"],
                str(prebuilt["candidate_bytes"]),
                prebuilt["build_receipt_sha256"],
                prebuilt["dependency_inventory_sha256"],
            )
        )
        preparation = launch["prebuilt_preparation"]
        values.extend(
            (
                preparation["path"],
                preparation["sha256"],
                preparation["schema"],
                preparation["python_runtime_inventory_path"],
                preparation["python_runtime_inventory_sha256"],
            )
        )
        for label in ("git", "sbatch", "scontrol", "scancel", "sacct"):
            tool = launch["control_tools"][label]
            values.extend((tool["path"], tool["sha256"], tool["version"]))
        sys.stdout.buffer.write(b"\0".join(value.encode("ascii") for value in values) + b"\0")
        return 0
    except (UnicodeEncodeError, ValidationError) as error:
        print(f"T11 launch manifest rejected: {error}", file=sys.stderr)
        return 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--metadata-out", type=Path, required=True)
    parser.add_argument("--launch-manifest", type=Path, required=True)
    parser.add_argument("--launch-manifest-sha256", required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--source-before-sha256", required=True)
    parser.add_argument("--source-after-sha256", required=True)
    parser.add_argument("--binary-before-sha256", required=True)
    parser.add_argument("--binary-after-sha256", required=True)
    parser.add_argument("--bundle-project-sha256", required=True)
    parser.add_argument("--bundle-audit-sha256", required=True)
    parser.add_argument("--project-exit", type=int, required=True)
    parser.add_argument("--audit-exit", type=int, required=True)
    parser.add_argument(
        "--artifact",
        action="append",
        nargs=3,
        metavar=("NAME", "ORIGINAL_PATH", "SNAPSHOT_PATH"),
        default=[],
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        validator_snapshot = _sealed_snapshot_path(
            Path(sys.argv[0]), "validator executable snapshot"
        )
        for label, path in (
            ("source", args.source),
            ("bundle", args.bundle),
            ("receipt", args.receipt),
            ("binary", args.binary),
            ("launch manifest", args.launch_manifest),
        ):
            _sealed_snapshot_path(path, f"{label} input")
        if not args.job_id.isascii() or not args.job_id.isdecimal():
            _fail("SLURM job ID must be a nonempty decimal integer")
        launch, launch_sha256, _ = _validate_launch_manifest(
            args.launch_manifest, args.launch_manifest_sha256
        )
        before = _canonical_sha256(args.source_before_sha256, "source-before SHA-256")
        after = _canonical_sha256(args.source_after_sha256, "source-after SHA-256")
        if before != TARGET_SHA256 or after != TARGET_SHA256 or before != after:
            _fail("source identity changed across Stage 0A")
        binary_before = _canonical_sha256(
            args.binary_before_sha256, "binary-before SHA-256"
        )
        binary_after = _canonical_sha256(
            args.binary_after_sha256, "binary-after SHA-256"
        )
        if binary_before != binary_after:
            _fail("binary bytes changed across Stage 0A")
        bundle_project = _canonical_sha256(
            args.bundle_project_sha256, "post-project bundle SHA-256"
        )
        bundle_audit = _canonical_sha256(
            args.bundle_audit_sha256, "post-audit bundle SHA-256"
        )
        if bundle_project != bundle_audit:
            _fail("bundle bytes changed between projection and audit")
        if args.project_exit != 4 or args.audit_exit != 0:
            _fail("Stage 0A command exit contract was not satisfied")

        evidence = validate_evidence(
            source_path=args.source,
            bundle_path=args.bundle,
            receipt_path=args.receipt,
        )
        artifacts = _parse_artifacts(args.artifact)
        artifact_records = {
            name: _artifact_record(snapshot, original)
            for name, (original, snapshot) in sorted(artifacts.items())
        }
        expected_snapshots = {
            "source": args.source,
            "bundle": args.bundle,
            "audit_receipt": args.receipt,
            "binary": args.binary,
            "launch_manifest": args.launch_manifest,
            "validator": validator_snapshot,
        }
        for name, expected_snapshot in expected_snapshots.items():
            if artifacts[name][1] != expected_snapshot:
                _fail(f"artifact {name} does not reuse its validated sealed snapshot")
        if artifact_records["source"]["sha256"] != TARGET_SHA256:
            _fail("metadata source artifact differs from the frozen target")
        if artifact_records["bundle"]["sha256"] != evidence["bundle_sha256"]:
            _fail("metadata bundle artifact differs from validated evidence")
        if artifact_records["audit_receipt"]["sha256"] != evidence["receipt_sha256"]:
            _fail("metadata receipt artifact differs from validated evidence")
        if artifact_records["launch_manifest"]["sha256"] != launch_sha256:
            _fail("metadata launch-manifest artifact differs from validated manifest")
        if bundle_project != evidence["bundle_sha256"]:
            _fail("validated bundle differs from the executed projection bundle")

        binary_record = artifact_records["binary"]
        if binary_record["sha256"] != binary_before:
            _fail("binary artifact differs from the executed binary bytes")
        prebuilt = launch["prebuilt_bundle"]
        if (
            binary_record["sha256"] != prebuilt["candidate_sha256"]
            or binary_record["bytes"] != prebuilt["candidate_bytes"]
        ):
            _fail("executed binary differs from the launch-pinned prebuilt candidate")
        if artifact_records["prebuilt_bundle"]["sha256"] != prebuilt["sha256"]:
            _fail("prebuilt bundle artifact differs from the launch manifest")
        preparation = launch["prebuilt_preparation"]
        if (
            artifact_records["prebuilt_preparation"]["sha256"]
            != preparation["sha256"]
        ):
            _fail("prebuilt preparation artifact differs from the launch manifest")
        if (
            artifact_records["python_runtime_inventory"]["sha256"]
            != preparation["python_runtime_inventory_sha256"]
        ):
            _fail("Python runtime inventory artifact differs from the preparation")
        if (
            artifact_records["build_receipt"]["sha256"]
            != prebuilt["build_receipt_sha256"]
        ):
            _fail("build receipt artifact differs from the launch manifest")
        if (
            artifact_records["dependency_inventory"]["sha256"]
            != prebuilt["dependency_inventory_sha256"]
        ):
            _fail("dependency inventory artifact differs from the launch manifest")

        build_receipt_value, _, _, _ = _load_exact_json(
            artifacts["build_receipt"][1]
        )
        build_receipt = _validate_prebuilt_build_receipt(
            build_receipt_value, launch["solver_source"], prebuilt
        )
        dependency_inventory_value, _, _, _ = _load_exact_json(
            artifacts["dependency_inventory"][1]
        )
        dependency_inventory = _validate_binary_dependency_inventory(
            dependency_inventory_value, prebuilt["candidate_sha256"]
        )
        if not dependency_inventory["runtime_files"]:
            _fail("candidate runtime inventory must be nonempty")
        python_inventory_value, _, _, _ = _load_exact_json(
            artifacts["python_runtime_inventory"][1]
        )
        python_runtime_inventory = _validate_binary_dependency_inventory(
            python_inventory_value, launch["toolchain"]["python"]["sha256"]
        )
        if not python_runtime_inventory["runtime_files"]:
            _fail("Python runtime inventory must be nonempty")

        for manifest_field, artifact_name in PINNED_ARTIFACT_HASH_FIELDS.items():
            if (
                artifact_records[artifact_name]["sha256"]
                != launch["artifacts"][manifest_field]
            ):
                _fail(f"artifact {artifact_name} differs from the launch manifest")

        control_git = launch["control_tools"]["git"]
        if (
            Path(artifact_records["control_git"]["path"])
            != Path(control_git["path"])
            or artifact_records["control_git"]["sha256"] != control_git["sha256"]
        ):
            _fail("artifact control_git differs from the launch manifest")

        manifest_toolchain = launch["toolchain"]
        if Path(artifact_records["python"]["path"]) != Path(
            manifest_toolchain["python"]["path"]
        ):
            _fail("artifact python original path differs from the launch manifest")
        toolchain = {
            "python": _tool_record(
                artifact_records["python"],
                manifest_toolchain["python"]["sha256"],
                manifest_toolchain["python"]["version"],
                "python",
            )
        }
        # Scheduler completion, runner stdout/stderr, and the final run-root
        # inventory do not exist yet.  This record is therefore deliberately
        # non-authorizing; only the post-job finalizer may promote it.
        payload = {
            "schema": SCHEMA,
            "status": "validated_candidate",
            "decision": "requires_scheduler_finalization",
            "stage0b_authority": False,
            "revision": launch["solver_revision"],
            "launch_manifest_sha256": launch_sha256,
            "job_id": int(args.job_id),
            "hostname": platform.node(),
            "resource_contract": {
                "cpus": 1,
                "memory_bytes": 8 * 1024**3,
                "sat_calls": 0,
            },
            "execution_contract": {
                "binary_source": "launch-pinned-prebuilt-bundle",
                "build_during_stage0a": False,
                "candidate_sealed_before_exec": True,
                "candidate_loader_closure_inventory_validated": True,
                "dynamic_loader_objects_descriptor_bound": False,
                "python_loader_closure_inventory_validated": True,
                "runtime_dependency_paths_retained": True,
                "runtime_dependency_paths_revalidated": True,
            },
            "prebuilt_bundle": prebuilt,
            "prebuilt_preparation": {
                "path": preparation["path"],
                "schema": preparation["schema"],
                "sha256": preparation["sha256"],
            },
            "build_receipt": build_receipt,
            "dependency_inventory": dependency_inventory,
            "python_runtime_inventory": python_runtime_inventory,
            "control_tools": launch["control_tools"],
            "target": {
                "relative_path": TARGET_RELATIVE_PATH,
                "source_sha256": TARGET_SHA256,
                "source_bytes": evidence["source_bytes"],
            },
            "baseline": {
                **EXPECTED_INPUT_COUNTERS,
                "atom_map_sha256": ATOM_MAP_SHA256,
                "baseline_cnf_sha256": BASELINE_CNF_SHA256,
                "baseline_problem_sha256": BASELINE_PROBLEM_SHA256,
            },
            "projection": {
                "project_exit": args.project_exit,
                "audit_exit": args.audit_exit,
                "outcome": evidence["outcome"],
                "counters": evidence["counters"],
                "checker_counters": evidence["checker_counters"],
                "hashes": evidence["hashes"],
                "exact_bundle_sha256": evidence["bundle_sha256"],
                "audit_receipt_sha256": evidence["receipt_sha256"],
                "executed_binary_sha256": binary_before,
            },
            "toolchain": toolchain,
            "artifacts": artifact_records,
        }
        binding = _write_immutable_json(args.metadata_out, payload)
        print(
            json.dumps(
                binding,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except ValidationError as error:
        print(f"T11 Stage 0A rejected: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "inspect-launch":
        raise SystemExit(inspect_launch_main(sys.argv[2:]))
    raise SystemExit(main())
