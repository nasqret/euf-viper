#!/usr/bin/env python3
r"""Independently audit a fetched WMI Fabric shadow artifact directory.

The operator must supply an independent expected revision, manifest SHA-256,
corpus mode, row count, and Slurm job ID. Neither the API nor CLI derives these
values from the submitted evidence.

CLI usage::

    audit_fabric_shadow.py ARTIFACTS SUBMISSION.json \
        --expected-revision REVISION \
        --expected-manifest-sha256 SHA256 \
        --expected-corpus-mode smoke|full \
        --expected-row-count ROWS \
        --expected-slurm-job-id JOB_ID \
        --out AUDIT.json

The emitted receipt verifies only a complete, bound F0 shadow census artifact.
It makes no solver-result, performance, or promotion claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import posixpath
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


AUDIT_SCHEMA = "euf-viper.fabric-shadow-offline-audit.v1"
SUBMISSION_SCHEMA = "euf-viper.fabric-shadow-wmi-submission.v1"
SLURM_SCHEMA = "euf-viper.fabric-shadow-wmi-run.v1"
FROZEN_FULL_MANIFEST_SHA256 = (
    "9c509b0ffd35a371738dbb31865f975b43350fca5f54393f7bb5014d450a08db"
)
HEX64 = frozenset("0123456789abcdef")
REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
SAFE_RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
SAFE_PARTITION_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
WALL_TIME_RE = re.compile(r"([0-9]{2}):([0-5][0-9]):([0-5][0-9])\Z")
POSITIVE_INTEGER_RE = re.compile(r"[1-9][0-9]*\Z")

ARTIFACT_FILES = frozenset(
    {
        "fabric-shadow.jsonl",
        "summary.json",
        "slurm.json",
        "euf-viper",
        "stdout.log",
        "stderr.log",
    }
)
SLURM_ARTIFACT_FILES = {
    "records": "fabric-shadow.jsonl",
    "summary": "summary.json",
    "solver": "euf-viper",
    "stdout": "stdout.log",
    "stderr": "stderr.log",
}
SUBMISSION_ARTIFACT_FILES = {
    "rows": "fabric-shadow.jsonl",
    "summary": "summary.json",
    "slurm": "slurm.json",
    "stdout": "stdout.log",
    "stderr": "stderr.log",
}

NON_CLAIM_SCOPE = {
    "stage": "F0",
    "mode": "semantic_substrate_shadow_census",
    "default_behavior_change": False,
    "solver_result_claim": False,
    "performance_claim": False,
    "promotion_claim": False,
    "solver_result_claims_allowed": 0,
}

RECEIPT_INTEGER_FIELDS = frozenset(
    {
        "source_bytes",
        "parse_ns",
        "projection_ns",
        "terms",
        "applications",
        "atoms",
        "assertions",
        "root_literals",
        "components",
        "max_component_terms",
        "cross_component_boolean_nodes",
        "unsupported_fragments",
    }
)
RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "mode",
        "solver_result_emitted",
        "contradiction",
        *RECEIPT_INTEGER_FIELDS,
    }
)
RECORD_FIELDS = frozenset(
    {
        *RECEIPT_FIELDS,
        "record_type",
        "manifest_index",
        "manifest_line",
        "id",
        "path",
        "relative_path",
        "resolved_path",
        "resolution_rule",
        "expected_status",
        "manifest_sha256",
        "input_binding_sha256",
        "input_sha256",
        "solver_path",
        "solver_sha256",
        "timeout_s",
        "wall_time_ns",
    }
)
COMPONENT_TOTAL_FIELDS = (
    "source_bytes",
    "terms",
    "applications",
    "atoms",
    "assertions",
    "root_literals",
    "components",
    "cross_component_boolean_nodes",
    "unsupported_fragments",
)

SUBMISSION_FIELDS = frozenset(
    {
        "schema",
        "status",
        "run_id",
        "scope",
        "revision",
        "published_ref",
        "corpus_mode",
        "remote_host",
        "work_root",
        "remote_worktree",
        "run_root",
        "manifest",
        "tools",
        "slurm",
        "resume",
        "submission_state_may_be_incomplete",
        "artifacts",
    }
)
SLURM_FIELDS = frozenset(
    {
        "schema",
        "status",
        "scope",
        "revision",
        "corpus_mode",
        "resume",
        "single_core",
        "jobs",
        "instance_timeout_s",
        "manifest",
        "slurm",
        "tools",
        "artifacts",
        "completed_at",
    }
)
SUMMARY_FIELDS = frozenset(
    {
        "schema_version",
        "mode",
        "status",
        "manifest_path",
        "manifest_sha256",
        "input_binding_sha256",
        "input_bytes",
        "solver_path",
        "solver_sha256",
        "out_jsonl_path",
        "out_jsonl_sha256",
        "resolution",
        "parameters",
        "counts",
        "aggregate_component_metrics",
        "timing_quantiles_ns",
        "error",
    }
)


class AuditError(RuntimeError):
    """An integrity or contract failure in the fetched evidence."""


class _DuplicateKeyError(ValueError):
    pass


@dataclass(frozen=True)
class FileSnapshot:
    name: str
    sha256: str
    size: int
    mode: int
    data: bytes


@dataclass(frozen=True)
class OperatorExpectations:
    revision: str
    manifest_sha256: str
    corpus_mode: str
    row_count: int
    slurm_job_id: int


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKeyError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r}")


def _ensure_finite_json(value: Any, context: str) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise AuditError(f"{context}: non-finite JSON number")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _ensure_finite_json(item, f"{context}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _ensure_finite_json(item, f"{context}.{key}")


def _parse_json_text(text: str, context: str) -> Any:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, _DuplicateKeyError, ValueError) as exc:
        raise AuditError(f"{context}: invalid JSON: {exc}") from exc
    _ensure_finite_json(value, context)
    return value


def _parse_ascii_document(snapshot: FileSnapshot, context: str) -> Any:
    try:
        text = snapshot.data.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise AuditError(f"{context}: JSON document is not ASCII: {exc}") from exc
    if not text or not text.endswith("\n") or "\r" in text:
        raise AuditError(f"{context}: JSON document must end in one LF convention")
    return _parse_json_text(text, context)


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_open_file(
    descriptor: int,
    *,
    name: str,
    expected: os.stat_result | None = None,
) -> FileSnapshot:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise AuditError(f"{name}: expected a regular file")
    if expected is not None and (
        before.st_dev != expected.st_dev or before.st_ino != expected.st_ino
    ):
        raise AuditError(f"{name}: file identity changed while it was opened")
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        chunks.append(chunk)
    after = os.fstat(descriptor)
    if _fingerprint(before) != _fingerprint(after):
        raise AuditError(f"{name}: file changed while it was read")
    data = b"".join(chunks)
    if len(data) != after.st_size:
        raise AuditError(f"{name}: short or inconsistent read")
    return FileSnapshot(name, digest.hexdigest(), after.st_size, after.st_mode, data)


def _snapshot_path(path: Path, context: str) -> tuple[Path, FileSnapshot]:
    absolute = Path(os.path.abspath(os.path.expanduser(str(path))))
    try:
        before = os.lstat(absolute)
    except OSError as exc:
        raise AuditError(f"{context}: cannot inspect {absolute}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode):
        raise AuditError(f"{context}: symlinks are forbidden: {absolute}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise AuditError(f"{context}: cannot open {absolute}: {exc}") from exc
    try:
        snapshot = _read_open_file(descriptor, name=context, expected=before)
    finally:
        os.close(descriptor)
    try:
        current = os.lstat(absolute)
    except OSError as exc:
        raise AuditError(f"{context}: path disappeared after reading: {exc}") from exc
    if current.st_dev != before.st_dev or current.st_ino != before.st_ino:
        raise AuditError(f"{context}: path identity changed while it was read")
    return absolute.resolve(strict=True), snapshot


def _snapshot_artifact_directory(
    path: Path,
) -> tuple[Path, dict[str, FileSnapshot]]:
    absolute = Path(os.path.abspath(os.path.expanduser(str(path))))
    try:
        before = os.lstat(absolute)
    except OSError as exc:
        raise AuditError(f"artifact directory: cannot inspect {absolute}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise AuditError("artifact directory must be a real, non-symlink directory")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        directory_fd = os.open(absolute, flags)
    except OSError as exc:
        raise AuditError(f"cannot open artifact directory {absolute}: {exc}") from exc
    try:
        opened = os.fstat(directory_fd)
        if opened.st_dev != before.st_dev or opened.st_ino != before.st_ino:
            raise AuditError("artifact directory identity changed while it was opened")
        names = set(os.listdir(directory_fd))
        if names != ARTIFACT_FILES:
            missing = sorted(ARTIFACT_FILES - names)
            unexpected = sorted(names - ARTIFACT_FILES)
            raise AuditError(
                "artifact directory contents differ; "
                f"missing={missing}, unexpected={unexpected}"
            )

        snapshots: dict[str, FileSnapshot] = {}
        physical_files: set[tuple[int, int]] = set()
        file_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for name in sorted(ARTIFACT_FILES):
            try:
                entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise AuditError(f"artifact {name}: cannot inspect: {exc}") from exc
            if stat.S_ISLNK(entry.st_mode) or not stat.S_ISREG(entry.st_mode):
                raise AuditError(f"artifact {name}: must be a regular non-symlink file")
            try:
                descriptor = os.open(name, file_flags, dir_fd=directory_fd)
            except OSError as exc:
                raise AuditError(f"artifact {name}: cannot open: {exc}") from exc
            try:
                snapshot = _read_open_file(
                    descriptor, name=f"artifact {name}", expected=entry
                )
            finally:
                os.close(descriptor)
            identity = (entry.st_dev, entry.st_ino)
            if identity in physical_files:
                raise AuditError(f"artifact {name}: duplicate physical file identity")
            physical_files.add(identity)
            snapshots[name] = snapshot

        after = os.fstat(directory_fd)
        if _fingerprint(opened) != _fingerprint(after):
            raise AuditError("artifact directory changed while it was audited")
    finally:
        os.close(directory_fd)

    try:
        current = os.lstat(absolute)
    except OSError as exc:
        raise AuditError(f"artifact directory disappeared after reading: {exc}") from exc
    if current.st_dev != before.st_dev or current.st_ino != before.st_ino:
        raise AuditError("artifact directory path identity changed during audit")
    if snapshots["euf-viper"].mode & 0o111 == 0:
        raise AuditError("artifact euf-viper: executable mode is missing")
    return absolute.resolve(strict=True), snapshots


def _require_object(value: Any, context: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise AuditError(f"{context}: expected a JSON object")
    return value


def _require_fields(
    value: Any, fields: Iterable[str], context: str
) -> dict[str, Any]:
    result = _require_object(value, context)
    expected = frozenset(fields)
    actual = frozenset(result)
    if actual != expected:
        raise AuditError(
            f"{context}: fields differ; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    return result


def _same_json(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            _same_json(actual[key], item) for key, item in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _same_json(left, right) for left, right in zip(actual, expected)
        )
    return bool(actual == expected)


def _require_exact(actual: Any, expected: Any, context: str) -> None:
    if not _same_json(actual, expected):
        raise AuditError(f"{context}: expected exact value {expected!r}, got {actual!r}")


def _require_string(value: Any, context: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value) or "\x00" in value:
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise AuditError(f"{context}: expected {qualifier}")
    return value


def _require_optional_string(value: Any, context: str) -> str | None:
    if value is None:
        return None
    return _require_string(value, context)


def _require_int(value: Any, context: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise AuditError(f"{context}: expected an integer >= {minimum}")
    return value


def _require_positive_float(value: Any, context: str) -> float:
    if type(value) is not float or not math.isfinite(value) or value <= 0:
        raise AuditError(f"{context}: expected a finite positive JSON float")
    return value


def _require_sha256(value: Any, context: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in HEX64 for character in value)
    ):
        raise AuditError(f"{context}: expected 64 lowercase hexadecimal digits")
    return value


def _validate_operator_expectations(
    *,
    expected_revision: str,
    expected_manifest_sha256: str,
    expected_corpus_mode: str,
    expected_row_count: int,
    expected_slurm_job_id: int,
) -> OperatorExpectations:
    if type(expected_revision) is not str or REVISION_RE.fullmatch(
        expected_revision
    ) is None:
        raise AuditError(
            "operator expectation revision must be exactly 40 lowercase hex digits"
        )
    _require_sha256(
        expected_manifest_sha256, "operator expectation manifest SHA-256"
    )
    if type(expected_corpus_mode) is not str or expected_corpus_mode not in {
        "smoke",
        "full",
    }:
        raise AuditError(
            "operator expectation corpus mode must be exactly 'smoke' or 'full'"
        )
    _require_int(
        expected_row_count, "operator expectation row count", minimum=1
    )
    _require_int(
        expected_slurm_job_id, "operator expectation Slurm job ID", minimum=1
    )
    if expected_corpus_mode == "full":
        _require_exact(
            expected_row_count,
            7503,
            "operator expectation full row count",
        )
        _require_exact(
            expected_manifest_sha256,
            FROZEN_FULL_MANIFEST_SHA256,
            "operator expectation full manifest SHA-256",
        )
    elif expected_row_count > 7503:
        raise AuditError(
            "operator expectation smoke row count exceeds the frozen corpus"
        )
    return OperatorExpectations(
        revision=expected_revision,
        manifest_sha256=expected_manifest_sha256,
        corpus_mode=expected_corpus_mode,
        row_count=expected_row_count,
        slurm_job_id=expected_slurm_job_id,
    )


def _require_remote_path(value: Any, context: str) -> str:
    path = _require_string(value, context)
    if "\\" in path or not path.startswith("/") or posixpath.normpath(path) != path:
        raise AuditError(f"{context}: expected a normalized absolute POSIX path")
    if any(part in {"", ".", ".."} for part in path[1:].split("/")):
        raise AuditError(f"{context}: path contains an empty or traversing component")
    return path


def _remote_child(root: str, name: str) -> str:
    return str(PurePosixPath(root) / name)


def _require_relative_path(value: Any, context: str) -> str:
    path = _require_string(value, context)
    if "\\" in path or path.startswith("/") or posixpath.normpath(path) != path:
        raise AuditError(f"{context}: expected a normalized relative POSIX path")
    if any(part in {"", ".", ".."} for part in path.split("/")):
        raise AuditError(f"{context}: relative path traverses or has empty components")
    return path


def _validate_scope(value: Any, context: str) -> None:
    _require_exact(value, NON_CLAIM_SCOPE, context)


def _validate_tool(
    value: Any,
    context: str,
    *,
    runner: bool = False,
) -> dict[str, Any]:
    fields = {"sha256"} if runner else {"path", "sha256", "version"}
    tool = _require_fields(value, fields, context)
    _require_sha256(tool["sha256"], f"{context}.sha256")
    if not runner:
        _require_remote_path(tool["path"], f"{context}.path")
        _require_string(tool["version"], f"{context}.version")
    return tool


def _validate_submission(value: Any) -> dict[str, Any]:
    submission = _require_fields(value, SUBMISSION_FIELDS, "submission")
    _require_exact(submission["schema"], SUBMISSION_SCHEMA, "submission.schema")
    _require_exact(submission["status"], "submitted", "submission.status")
    run_id = _require_string(submission["run_id"], "submission.run_id")
    if SAFE_RUN_ID_RE.fullmatch(run_id) is None:
        raise AuditError("submission.run_id: unsafe run identifier")
    _validate_scope(submission["scope"], "submission.scope")
    revision = _require_string(submission["revision"], "submission.revision")
    if REVISION_RE.fullmatch(revision) is None:
        raise AuditError("submission.revision: expected 40 lowercase hex digits")
    published_ref = _require_string(
        submission["published_ref"], "submission.published_ref"
    )
    if not published_ref.startswith("refs/heads/") or ".." in published_ref.split("/"):
        raise AuditError("submission.published_ref: expected a safe branch reference")
    if submission["corpus_mode"] not in {"full", "smoke"}:
        raise AuditError("submission.corpus_mode: expected 'full' or 'smoke'")
    _require_string(submission["remote_host"], "submission.remote_host")

    work_root = _require_remote_path(submission["work_root"], "submission.work_root")
    remote_worktree = _require_remote_path(
        submission["remote_worktree"], "submission.remote_worktree"
    )
    run_root = _require_remote_path(submission["run_root"], "submission.run_root")
    expected_worktree_prefix = _remote_child(work_root, "checkouts") + "/"
    expected_run_prefix = _remote_child(work_root, "runs") + "/"
    if not remote_worktree.startswith(expected_worktree_prefix):
        raise AuditError("submission.remote_worktree escapes work_root/checkouts")
    if not run_root.startswith(expected_run_prefix):
        raise AuditError("submission.run_root escapes work_root/runs")

    manifest = _require_fields(
        submission["manifest"],
        {"path", "sha256", "expected_sources", "corpus_root", "corpus_access"},
        "submission.manifest",
    )
    _require_remote_path(manifest["path"], "submission.manifest.path")
    _require_sha256(manifest["sha256"], "submission.manifest.sha256")
    source_count = _require_int(
        manifest["expected_sources"], "submission.manifest.expected_sources", minimum=1
    )
    corpus_root = _require_remote_path(
        manifest["corpus_root"], "submission.manifest.corpus_root"
    )
    _require_exact(
        manifest["corpus_access"], "read_only", "submission.manifest.corpus_access"
    )
    if submission["corpus_mode"] == "full":
        _require_exact(source_count, 7503, "submission full source count")
        _require_exact(
            manifest["sha256"],
            FROZEN_FULL_MANIFEST_SHA256,
            "submission full manifest hash",
        )
    elif source_count > 7503:
        raise AuditError("submission smoke source count exceeds the frozen corpus")
    if run_root == corpus_root or run_root.startswith(corpus_root + "/"):
        raise AuditError("submission.run_root is inside the read-only corpus root")

    tools = _require_fields(
        submission["tools"], {"runner", "cargo", "rustc", "python"}, "submission.tools"
    )
    _validate_tool(tools["runner"], "submission.tools.runner", runner=True)
    cargo = _validate_tool(tools["cargo"], "submission.tools.cargo")
    rustc = _validate_tool(tools["rustc"], "submission.tools.rustc")
    python = _validate_tool(tools["python"], "submission.tools.python")
    if not cargo["version"].startswith("cargo 1.93.0 "):
        raise AuditError("submission.tools.cargo.version: expected cargo 1.93.0")
    if not rustc["version"].startswith("rustc 1.93.0 "):
        raise AuditError("submission.tools.rustc.version: expected rustc 1.93.0")
    if not python["version"].startswith("Python 3."):
        raise AuditError("submission.tools.python.version: expected Python 3")

    slurm = _require_fields(
        submission["slurm"],
        {
            "job_id",
            "cluster",
            "partition",
            "wall_time",
            "dependency",
            "cpus_per_task",
            "runner_jobs",
            "instance_timeout_s",
            "raw_submission",
        },
        "submission.slurm",
    )
    job_id = _require_int(slurm["job_id"], "submission.slurm.job_id", minimum=1)
    cluster = _require_optional_string(slurm["cluster"], "submission.slurm.cluster")
    partition = _require_string(slurm["partition"], "submission.slurm.partition")
    if SAFE_PARTITION_RE.fullmatch(partition) is None:
        raise AuditError("submission.slurm.partition: unsafe partition name")
    wall_time = _require_string(slurm["wall_time"], "submission.slurm.wall_time")
    match = WALL_TIME_RE.fullmatch(wall_time)
    if match is None or sum(
        int(part) * multiplier
        for part, multiplier in zip(match.groups(), (3600, 60, 1))
    ) == 0:
        raise AuditError("submission.slurm.wall_time: invalid or zero wall time")
    dependency = slurm["dependency"]
    if dependency is not None:
        dependency = _require_string(dependency, "submission.slurm.dependency")
        if not dependency.startswith("afterok:") or POSITIVE_INTEGER_RE.fullmatch(
            dependency.removeprefix("afterok:")
        ) is None:
            raise AuditError("submission.slurm.dependency: invalid afterok dependency")
    _require_exact(slurm["cpus_per_task"], 1, "submission.slurm.cpus_per_task")
    _require_exact(slurm["runner_jobs"], 1, "submission.slurm.runner_jobs")
    _require_positive_float(
        slurm["instance_timeout_s"], "submission.slurm.instance_timeout_s"
    )
    raw_submission = _require_string(
        slurm["raw_submission"], "submission.slurm.raw_submission"
    )
    expected_raw = str(job_id) if cluster is None else f"{job_id};{cluster}"
    _require_exact(raw_submission, expected_raw, "submission.slurm.raw_submission")

    if type(submission["resume"]) is not bool:
        raise AuditError("submission.resume: expected a Boolean")
    _require_exact(
        submission["submission_state_may_be_incomplete"],
        False,
        "submission.submission_state_may_be_incomplete",
    )
    artifact_root = _remote_child(run_root, "artifacts")
    artifacts = _require_fields(
        submission["artifacts"],
        {"root", *SUBMISSION_ARTIFACT_FILES},
        "submission.artifacts",
    )
    _require_exact(artifacts["root"], artifact_root, "submission.artifacts.root")
    for key, filename in SUBMISSION_ARTIFACT_FILES.items():
        _require_exact(
            artifacts[key],
            _remote_child(artifact_root, filename),
            f"submission.artifacts.{key}",
        )
    return submission


def _validate_slurm(
    value: Any,
    submission: Mapping[str, Any],
    snapshots: Mapping[str, FileSnapshot],
) -> dict[str, Any]:
    slurm = _require_fields(value, SLURM_FIELDS, "slurm receipt")
    _require_exact(slurm["schema"], SLURM_SCHEMA, "slurm receipt.schema")
    _require_exact(slurm["status"], "artifact_complete", "slurm receipt.status")
    _validate_scope(slurm["scope"], "slurm receipt.scope")
    for field in ("revision", "corpus_mode", "resume"):
        _require_exact(
            slurm[field], submission[field], f"slurm receipt.{field} binding"
        )
    _require_exact(slurm["single_core"], True, "slurm receipt.single_core")
    _require_exact(slurm["jobs"], 1, "slurm receipt.jobs")
    timeout = _require_positive_float(
        slurm["instance_timeout_s"], "slurm receipt.instance_timeout_s"
    )
    _require_exact(
        timeout,
        submission["slurm"]["instance_timeout_s"],
        "slurm receipt timeout binding",
    )

    manifest = _require_fields(
        slurm["manifest"],
        {
            "path",
            "corpus_root",
            "corpus_access",
            "sha256",
            "expected_sources",
            "observed_records",
        },
        "slurm receipt.manifest",
    )
    for field in ("path", "corpus_root", "corpus_access", "sha256", "expected_sources"):
        _require_exact(
            manifest[field],
            submission["manifest"][field],
            f"slurm receipt.manifest.{field} binding",
        )
    _require_exact(
        manifest["observed_records"],
        manifest["expected_sources"],
        "slurm receipt.manifest.observed_records",
    )

    allocation = _require_fields(
        slurm["slurm"],
        {
            "job_id",
            "job_name",
            "cluster",
            "partition",
            "account",
            "node_list",
            "cpus_per_task",
            "submit_dir",
        },
        "slurm receipt.slurm",
    )
    job_id = _require_string(allocation["job_id"], "slurm receipt.slurm.job_id")
    if POSITIVE_INTEGER_RE.fullmatch(job_id) is None:
        raise AuditError("slurm receipt.slurm.job_id: expected canonical positive integer")
    _require_exact(
        int(job_id), submission["slurm"]["job_id"], "Slurm job ID binding"
    )
    _require_exact(
        allocation["job_name"], "euf-fabric-shadow", "Slurm job name binding"
    )
    _require_exact(
        _require_string(allocation["partition"], "slurm receipt.slurm.partition"),
        submission["slurm"]["partition"],
        "Slurm partition binding",
    )
    _require_string(allocation["account"], "slurm receipt.slurm.account")
    _require_string(allocation["node_list"], "slurm receipt.slurm.node_list")
    _require_optional_string(allocation["cluster"], "slurm receipt.slurm.cluster")
    submission_cluster = submission["slurm"]["cluster"]
    if submission_cluster is not None:
        _require_exact(
            allocation["cluster"], submission_cluster, "Slurm cluster binding"
        )
    _require_exact(allocation["cpus_per_task"], 1, "slurm receipt CPUs")
    _require_exact(
        allocation["submit_dir"],
        submission["remote_worktree"],
        "Slurm submit directory binding",
    )

    tools = _require_fields(
        slurm["tools"], {"runner", "python", "cargo", "rustc"}, "slurm receipt.tools"
    )
    runner = _require_fields(
        tools["runner"], {"path", "sha256"}, "slurm receipt.tools.runner"
    )
    _require_exact(
        runner["path"],
        _remote_child(submission["remote_worktree"], "scripts/bench/run_fabric_shadow.py"),
        "runner path binding",
    )
    _require_sha256(runner["sha256"], "slurm receipt.tools.runner.sha256")
    _require_exact(
        runner["sha256"],
        submission["tools"]["runner"]["sha256"],
        "runner hash binding",
    )
    for name in ("python", "cargo", "rustc"):
        tool = _validate_tool(tools[name], f"slurm receipt.tools.{name}")
        _require_exact(tool, submission["tools"][name], f"{name} tool binding")

    final_root = submission["artifacts"]["root"]
    artifacts = _require_fields(
        slurm["artifacts"], SLURM_ARTIFACT_FILES, "slurm receipt.artifacts"
    )
    for key, filename in SLURM_ARTIFACT_FILES.items():
        entry = _require_fields(
            artifacts[key], {"path", "sha256", "bytes"}, f"slurm artifact {key}"
        )
        _require_exact(
            entry["path"], _remote_child(final_root, filename), f"{key} artifact path"
        )
        _require_sha256(entry["sha256"], f"{key} artifact hash")
        _require_int(entry["bytes"], f"{key} artifact bytes")
        snapshot = snapshots[filename]
        _require_exact(entry["sha256"], snapshot.sha256, f"{key} local hash binding")
        _require_exact(entry["bytes"], snapshot.size, f"{key} local byte binding")

    completed = _require_string(slurm["completed_at"], "slurm receipt.completed_at")
    if not completed.endswith("Z"):
        raise AuditError("slurm receipt.completed_at: expected UTC Z timestamp")
    try:
        parsed = datetime.fromisoformat(completed[:-1] + "+00:00")
    except ValueError as exc:
        raise AuditError("slurm receipt.completed_at: invalid timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        raise AuditError("slurm receipt.completed_at: expected UTC timestamp")
    return slurm


def _canonical_json_line(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _validate_record_shape(record: Any, context: str) -> dict[str, Any]:
    value = _require_fields(record, RECORD_FIELDS, context)
    _require_exact(value["record_type"], "fabric_shadow_receipt", f"{context}.record_type")
    _require_exact(value["schema_version"], 1, f"{context}.schema_version")
    _require_exact(value["mode"], "fabric_shadow", f"{context}.mode")
    _require_exact(
        value["solver_result_emitted"], False, f"{context}.solver_result_emitted"
    )
    for field in RECEIPT_INTEGER_FIELDS:
        _require_int(value[field], f"{context}.{field}")
    if type(value["contradiction"]) is not bool:
        raise AuditError(f"{context}.contradiction: expected a Boolean")
    _require_int(value["manifest_index"], f"{context}.manifest_index")
    _require_int(value["manifest_line"], f"{context}.manifest_line", minimum=1)
    identifier = value["id"]
    if (
        isinstance(identifier, bool)
        or not isinstance(identifier, (str, int))
        or (isinstance(identifier, str) and not identifier)
    ):
        raise AuditError(f"{context}.id: expected a non-empty string or integer")
    if value["path"] is not None:
        _require_string(value["path"], f"{context}.path")
    _require_relative_path(value["relative_path"], f"{context}.relative_path")
    _require_remote_path(value["resolved_path"], f"{context}.resolved_path")
    _require_string(value["resolution_rule"], f"{context}.resolution_rule")
    _require_string(value["expected_status"], f"{context}.expected_status")
    for field in ("manifest_sha256", "input_binding_sha256", "input_sha256", "solver_sha256"):
        _require_sha256(value[field], f"{context}.{field}")
    _require_remote_path(value["solver_path"], f"{context}.solver_path")
    _require_positive_float(value["timeout_s"], f"{context}.timeout_s")
    _require_int(value["wall_time_ns"], f"{context}.wall_time_ns")
    return value


def _parse_records(snapshot: FileSnapshot) -> list[dict[str, Any]]:
    try:
        text = snapshot.data.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise AuditError(f"records: JSONL is not ASCII: {exc}") from exc
    if not text or not text.endswith("\n") or "\r" in text:
        raise AuditError("records: JSONL must be non-empty and LF-terminated")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            raise AuditError(f"records:{line_number}: blank lines are forbidden")
        value = _parse_json_text(line, f"records:{line_number}")
        record = _validate_record_shape(value, f"records:{line_number}")
        if _canonical_json_line(record) != (line + "\n").encode("ascii"):
            raise AuditError(f"records:{line_number}: record is not canonical JSON")
        records.append(record)
    return records


def _input_binding_sha256(records: Sequence[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for record in records:
        binding = {
            "manifest_index": record["manifest_index"],
            "manifest_line": record["manifest_line"],
            "id": record["id"],
            "path": record["path"],
            "relative_path": record["relative_path"],
            "resolved_path": record["resolved_path"],
            "resolution_rule": record["resolution_rule"],
            "expected_status": record["expected_status"],
            "input_sha256": record["input_sha256"],
            "source_bytes": record["source_bytes"],
        }
        digest.update(_canonical_json_line(binding))
    return digest.hexdigest()


def _validate_records(
    records: Sequence[dict[str, Any]],
    submission: Mapping[str, Any],
    slurm: Mapping[str, Any],
    solver_snapshot: FileSnapshot,
) -> str:
    expected_count = submission["manifest"]["expected_sources"]
    _require_exact(len(records), expected_count, "records complete row count")
    manifest_hash = submission["manifest"]["sha256"]
    timeout = submission["slurm"]["instance_timeout_s"]
    corpus_root = submission["manifest"]["corpus_root"]
    staging_root = _remote_child(submission["run_root"], ".artifacts.partial")
    solver_path = _remote_child(staging_root, "euf-viper")
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    claimed_binding: str | None = None

    for index, record in enumerate(records):
        context = f"records:{index + 1}"
        _require_exact(record["manifest_index"], index, f"{context}.manifest_index order")
        _require_exact(record["manifest_line"], index + 1, f"{context}.manifest_line order")
        identity = str(record["id"])
        if identity in seen_ids:
            raise AuditError(f"{context}.id: duplicate manifest identity {identity!r}")
        seen_ids.add(identity)
        relative = record["relative_path"]
        if relative in seen_paths:
            raise AuditError(f"{context}.relative_path: duplicate path {relative!r}")
        seen_paths.add(relative)
        expected_resolved = _remote_child(corpus_root, relative)
        _require_exact(
            record["resolved_path"], expected_resolved, f"{context}.resolved_path binding"
        )
        _require_exact(
            record["resolution_rule"],
            "corpus_root_relative_path",
            f"{context}.resolution_rule",
        )
        _require_exact(record["manifest_sha256"], manifest_hash, f"{context} manifest binding")
        _require_exact(record["solver_path"], solver_path, f"{context} solver path binding")
        _require_exact(
            record["solver_sha256"],
            solver_snapshot.sha256,
            f"{context} solver hash binding",
        )
        _require_exact(record["timeout_s"], timeout, f"{context} timeout binding")
        if claimed_binding is None:
            claimed_binding = record["input_binding_sha256"]
        else:
            _require_exact(
                record["input_binding_sha256"],
                claimed_binding,
                f"{context} input binding consistency",
            )

    computed_binding = _input_binding_sha256(records)
    _require_exact(claimed_binding, computed_binding, "records input binding digest")
    _require_exact(
        slurm["manifest"]["observed_records"], len(records), "Slurm observed record count"
    )
    return computed_binding


def _quantiles(values: Sequence[int]) -> dict[str, int]:
    ordered = sorted(values)
    if not ordered:
        raise AuditError("cannot audit quantiles for an empty complete census")

    def nearest_rank(percentile: int) -> int:
        index = max(0, math.ceil((percentile / 100) * len(ordered)) - 1)
        return ordered[index]

    return {
        "count": len(ordered),
        "total": sum(ordered),
        "min": ordered[0],
        "p50": nearest_rank(50),
        "p90": nearest_rank(90),
        "p95": nearest_rank(95),
        "p99": nearest_rank(99),
        "max": ordered[-1],
    }


def _validate_summary(
    value: Any,
    records: Sequence[Mapping[str, Any]],
    submission: Mapping[str, Any],
    slurm: Mapping[str, Any],
    snapshots: Mapping[str, FileSnapshot],
    binding_sha256: str,
) -> dict[str, Any]:
    summary = _require_fields(value, SUMMARY_FIELDS, "summary")
    _require_exact(summary["schema_version"], 1, "summary.schema_version")
    _require_exact(summary["mode"], "fabric_shadow", "summary.mode")
    _require_exact(summary["status"], "complete", "summary.status")
    _require_exact(summary["error"], None, "summary.error")
    _require_exact(
        summary["manifest_path"], submission["manifest"]["path"], "summary manifest path"
    )
    _require_exact(
        summary["manifest_sha256"],
        submission["manifest"]["sha256"],
        "summary manifest hash",
    )
    _require_exact(summary["input_binding_sha256"], binding_sha256, "summary input binding")
    _require_exact(
        summary["input_bytes"],
        sum(record["source_bytes"] for record in records),
        "summary input bytes",
    )
    staging_root = _remote_child(submission["run_root"], ".artifacts.partial")
    _require_exact(
        summary["solver_path"],
        _remote_child(staging_root, "euf-viper"),
        "summary solver path",
    )
    _require_exact(
        summary["solver_sha256"], snapshots["euf-viper"].sha256, "summary solver hash"
    )
    _require_exact(
        summary["out_jsonl_path"],
        _remote_child(staging_root, "fabric-shadow.jsonl"),
        "summary records path",
    )
    _require_exact(
        summary["out_jsonl_sha256"],
        snapshots["fabric-shadow.jsonl"].sha256,
        "summary records hash",
    )

    resolution = _require_fields(
        summary["resolution"],
        {
            "rule",
            "corpus_root",
            "invocation_cwd",
            "declared_paths",
            "repository_root",
            "repository_layout",
            "repository_layout_enabled",
            "resolved_by_rule",
            "ambiguity_policy",
            "traversal_policy",
        },
        "summary.resolution",
    )
    expected_resolution = {
        "rule": "corpus_root_plus_relative_path_and_repository_layout_when_repo_root",
        "corpus_root": submission["manifest"]["corpus_root"],
        "invocation_cwd": None,
        "declared_paths": "preserved_but_ignored",
        "repository_root": submission["remote_worktree"],
        "repository_layout": "benchmarks/smtlib-2025/QF_UF",
        "repository_layout_enabled": False,
        "resolved_by_rule": {"corpus_root_relative_path": len(records)},
        "ambiguity_policy": "reject",
        "traversal_policy": "normalized_relative_and_resolved_containment",
    }
    _require_exact(resolution, expected_resolution, "summary.resolution")

    parameters = _require_fields(
        summary["parameters"], {"jobs", "timeout_s", "resume"}, "summary.parameters"
    )
    _require_exact(parameters["jobs"], 1, "summary.parameters.jobs")
    _require_exact(
        parameters["timeout_s"],
        submission["slurm"]["instance_timeout_s"],
        "summary timeout binding",
    )
    _require_exact(parameters["resume"], submission["resume"], "summary resume binding")

    count = len(records)
    counts = _require_fields(
        summary["counts"],
        {
            "manifest_rows",
            "preexisting_rows",
            "selected_rows",
            "attempted_rows",
            "completed_rows",
            "error_rows",
            "remaining_rows",
        },
        "summary.counts",
    )
    for field in counts:
        _require_int(counts[field], f"summary.counts.{field}")
    _require_exact(counts["manifest_rows"], count, "summary manifest count")
    _require_exact(counts["completed_rows"], count, "summary completed count")
    _require_exact(counts["error_rows"], 0, "summary error count")
    _require_exact(counts["remaining_rows"], 0, "summary remaining count")
    preexisting = counts["preexisting_rows"]
    if preexisting > count:
        raise AuditError("summary.counts.preexisting_rows exceeds manifest count")
    if submission["resume"] and preexisting == 0:
        raise AuditError("summary resume run has no preexisting rows")
    if not submission["resume"] and preexisting != 0:
        raise AuditError("summary fresh run has preexisting rows")
    _require_exact(counts["selected_rows"], count - preexisting, "summary selected count")
    _require_exact(counts["attempted_rows"], count - preexisting, "summary attempted count")

    aggregate = {
        field: sum(record[field] for record in records)
        for field in COMPONENT_TOTAL_FIELDS
    }
    aggregate["max_component_terms"] = max(
        record["max_component_terms"] for record in records
    )
    aggregate["contradiction_instances"] = sum(
        int(record["contradiction"]) for record in records
    )
    expected_aggregate_fields = {*COMPONENT_TOTAL_FIELDS, "max_component_terms", "contradiction_instances"}
    actual_aggregate = _require_fields(
        summary["aggregate_component_metrics"],
        expected_aggregate_fields,
        "summary.aggregate_component_metrics",
    )
    for field in actual_aggregate:
        _require_int(actual_aggregate[field], f"summary.aggregate_component_metrics.{field}")
    _require_exact(actual_aggregate, aggregate, "summary aggregate metrics")

    expected_timing = {
        field: _quantiles([record[field] for record in records])
        for field in ("wall_time_ns", "parse_ns", "projection_ns")
    }
    timing = _require_fields(
        summary["timing_quantiles_ns"], expected_timing, "summary.timing_quantiles_ns"
    )
    for field, quantiles in timing.items():
        actual = _require_fields(
            quantiles,
            {"count", "total", "min", "p50", "p90", "p95", "p99", "max"},
            f"summary.timing_quantiles_ns.{field}",
        )
        for name in actual:
            _require_int(actual[name], f"summary.timing_quantiles_ns.{field}.{name}")
    _require_exact(timing, expected_timing, "summary timing quantiles")
    _require_exact(slurm["manifest"]["observed_records"], count, "complete Slurm count")
    return summary


def _validate_stdout(snapshot: FileSnapshot, count: int) -> None:
    expected = (
        f"status=complete manifest_rows={count} completed_rows={count} "
        "remaining_rows=0\n"
    ).encode("ascii")
    _require_exact(snapshot.data, expected, "runner stdout log")


def _enforce_operator_expectations(
    expectations: OperatorExpectations,
    submission: Mapping[str, Any],
    slurm: Mapping[str, Any],
    summary: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
) -> None:
    for context, actual in (
        ("submission revision", submission["revision"]),
        ("Slurm revision", slurm["revision"]),
    ):
        _require_exact(
            actual,
            expectations.revision,
            f"operator expectation {context}",
        )

    for context, actual in (
        ("submission corpus mode", submission["corpus_mode"]),
        ("Slurm corpus mode", slurm["corpus_mode"]),
    ):
        _require_exact(
            actual,
            expectations.corpus_mode,
            f"operator expectation {context}",
        )

    manifest_values: list[tuple[str, Any]] = [
        ("submission manifest SHA-256", submission["manifest"]["sha256"]),
        ("Slurm manifest SHA-256", slurm["manifest"]["sha256"]),
        ("summary manifest SHA-256", summary["manifest_sha256"]),
    ]
    manifest_values.extend(
        (f"record {index + 1} manifest SHA-256", record["manifest_sha256"])
        for index, record in enumerate(records)
    )
    for context, actual in manifest_values:
        _require_exact(
            actual,
            expectations.manifest_sha256,
            f"operator expectation {context}",
        )

    row_counts = (
        ("submission row count", submission["manifest"]["expected_sources"]),
        ("Slurm expected row count", slurm["manifest"]["expected_sources"]),
        ("Slurm observed row count", slurm["manifest"]["observed_records"]),
        ("summary manifest row count", summary["counts"]["manifest_rows"]),
        ("summary completed row count", summary["counts"]["completed_rows"]),
        ("records row count", len(records)),
    )
    for context, actual in row_counts:
        _require_exact(
            actual,
            expectations.row_count,
            f"operator expectation {context}",
        )

    _require_exact(
        submission["slurm"]["job_id"],
        expectations.slurm_job_id,
        "operator expectation submission Slurm job ID",
    )
    _require_exact(
        slurm["slurm"]["job_id"],
        str(expectations.slurm_job_id),
        "operator expectation artifact Slurm job ID",
    )


def audit_fabric_shadow(
    artifact_directory: Path,
    submission_receipt: Path,
    *,
    expected_revision: str,
    expected_manifest_sha256: str,
    expected_corpus_mode: str,
    expected_row_count: int,
    expected_slurm_job_id: int,
) -> dict[str, Any]:
    """Audit evidence against mandatory independent operator expectations.

    All five ``expected_*`` arguments are required and must originate outside
    the artifact bundle. The function never substitutes values read from the
    submission receipt, Slurm receipt, summary, or JSONL records.
    """
    expectations = _validate_operator_expectations(
        expected_revision=expected_revision,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_corpus_mode=expected_corpus_mode,
        expected_row_count=expected_row_count,
        expected_slurm_job_id=expected_slurm_job_id,
    )
    artifact_path, snapshots = _snapshot_artifact_directory(artifact_directory)
    submission_path, submission_snapshot = _snapshot_path(
        submission_receipt, "submission receipt"
    )
    submission = _validate_submission(
        _parse_ascii_document(submission_snapshot, "submission receipt")
    )
    slurm = _validate_slurm(
        _parse_ascii_document(snapshots["slurm.json"], "slurm receipt"),
        submission,
        snapshots,
    )
    records = _parse_records(snapshots["fabric-shadow.jsonl"])
    binding_sha256 = _validate_records(
        records, submission, slurm, snapshots["euf-viper"]
    )
    summary = _validate_summary(
        _parse_ascii_document(snapshots["summary.json"], "summary"),
        records,
        submission,
        slurm,
        snapshots,
        binding_sha256,
    )
    _validate_stdout(snapshots["stdout.log"], len(records))
    _enforce_operator_expectations(
        expectations,
        submission,
        slurm,
        summary,
        records,
    )

    artifact_inputs = {
        name: {
            "path": str(artifact_path / name),
            "sha256": snapshot.sha256,
            "bytes": snapshot.size,
        }
        for name, snapshot in sorted(snapshots.items())
    }
    return {
        "schema": AUDIT_SCHEMA,
        "status": "verified",
        "scope": {
            **NON_CLAIM_SCOPE,
            "verification": "complete_bound_shadow_census_artifact",
            "verified": True,
        },
        "revision": expectations.revision,
        "corpus_mode": expectations.corpus_mode,
        "job_id": expectations.slurm_job_id,
        "operator_expectations": {
            "revision": expectations.revision,
            "manifest_sha256": expectations.manifest_sha256,
            "corpus_mode": expectations.corpus_mode,
            "row_count": expectations.row_count,
            "slurm_job_id": expectations.slurm_job_id,
            "source": "independent_operator_input",
        },
        "manifest": {
            "sha256": expectations.manifest_sha256,
            "rows": expectations.row_count,
            "corpus_root": submission["manifest"]["corpus_root"],
        },
        "bindings": {
            "input_binding_sha256": binding_sha256,
            "solver_sha256": snapshots["euf-viper"].sha256,
            "runner_sha256": submission["tools"]["runner"]["sha256"],
            "cargo_sha256": submission["tools"]["cargo"]["sha256"],
            "rustc_sha256": submission["tools"]["rustc"]["sha256"],
            "python_sha256": submission["tools"]["python"]["sha256"],
        },
        "counts": {
            "manifest_rows": len(records),
            "completed_rows": len(records),
            "error_rows": 0,
            "missing_rows": 0,
            "duplicate_rows": 0,
            "solver_result_claims": 0,
        },
        "inputs": {
            "artifact_directory": str(artifact_path),
            "submission_receipt": {
                "path": str(submission_path),
                "sha256": submission_snapshot.sha256,
                "bytes": submission_snapshot.size,
            },
            "artifacts": artifact_inputs,
        },
        "audited_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def _atomic_write_receipt(path: Path, payload: Mapping[str, Any]) -> Path:
    output = Path(os.path.abspath(os.path.expanduser(str(path))))
    output.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(output):
        raise AuditError(f"audit receipt already exists: {output}")
    encoded = (
        json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    descriptor, temporary_raw = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    temporary = Path(temporary_raw)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, output)
        except FileExistsError as exc:
            raise AuditError(f"audit receipt already exists: {output}") from exc
        directory_fd = os.open(output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
    return output


def _revision_argument(value: str) -> str:
    if REVISION_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "must be exactly 40 lowercase hexadecimal digits"
        )
    return value


def _sha256_argument(value: str) -> str:
    if len(value) != 64 or any(character not in HEX64 for character in value):
        raise argparse.ArgumentTypeError(
            "must be exactly 64 lowercase hexadecimal digits"
        )
    return value


def _positive_integer_argument(value: str) -> int:
    if POSITIVE_INTEGER_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("must be a canonical positive integer")
    return int(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("artifact_directory", type=Path)
    parser.add_argument("submission_receipt", type=Path)
    parser.add_argument(
        "--expected-revision",
        type=_revision_argument,
        required=True,
        help="independently recorded exact 40-hex Git revision",
    )
    parser.add_argument(
        "--expected-manifest-sha256",
        type=_sha256_argument,
        required=True,
        help="independently recorded manifest SHA-256",
    )
    parser.add_argument(
        "--expected-corpus-mode",
        choices=("smoke", "full"),
        required=True,
        help="independently selected corpus mode",
    )
    parser.add_argument(
        "--expected-row-count",
        type=_positive_integer_argument,
        required=True,
        help="independently recorded exact manifest row count",
    )
    parser.add_argument(
        "--expected-slurm-job-id",
        type=_positive_integer_argument,
        required=True,
        help="independently recorded exact Slurm job ID",
    )
    parser.add_argument("--out", type=Path, required=True, help="new atomic audit receipt")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    artifact_absolute = Path(
        os.path.abspath(os.path.expanduser(str(args.artifact_directory)))
    )
    submission_absolute = Path(
        os.path.abspath(os.path.expanduser(str(args.submission_receipt)))
    )
    output_absolute = Path(os.path.abspath(os.path.expanduser(str(args.out))))
    try:
        payload = audit_fabric_shadow(
            artifact_absolute,
            submission_absolute,
            expected_revision=args.expected_revision,
            expected_manifest_sha256=args.expected_manifest_sha256,
            expected_corpus_mode=args.expected_corpus_mode,
            expected_row_count=args.expected_row_count,
            expected_slurm_job_id=args.expected_slurm_job_id,
        )
        output_absolute.parent.mkdir(parents=True, exist_ok=True)
        output_absolute = output_absolute.parent.resolve(strict=True) / output_absolute.name
        canonical_artifact = Path(payload["inputs"]["artifact_directory"])
        canonical_submission = Path(payload["inputs"]["submission_receipt"]["path"])
        try:
            output_absolute.relative_to(canonical_artifact)
        except ValueError:
            pass
        else:
            raise AuditError("audit receipt must be outside the audited artifact directory")
        if output_absolute == canonical_submission:
            raise AuditError("audit receipt must not replace the submission receipt")
        output = _atomic_write_receipt(output_absolute, payload)
    except (AuditError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"verified receipt={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
