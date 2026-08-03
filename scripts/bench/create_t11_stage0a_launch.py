#!/usr/bin/env python3
"""Create and independently validate one exact T11 Stage 0A launch manifest."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


_VALIDATOR_PATH = Path(__file__).resolve().with_name("validate_t11_stage0a.py")
_VALIDATOR_SPEC = importlib.util.spec_from_file_location(
    "validate_t11_stage0a_for_launch", _VALIDATOR_PATH
)
if _VALIDATOR_SPEC is None or _VALIDATOR_SPEC.loader is None:
    raise RuntimeError("cannot load adjacent T11 launch validator")
validator = importlib.util.module_from_spec(_VALIDATOR_SPEC)
sys.modules[_VALIDATOR_SPEC.name] = validator
_VALIDATOR_SPEC.loader.exec_module(validator)


SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 1024 * 1024

PINNED_ARTIFACT_PATHS = {
    "submitter_sha256": "scripts/wmi/submit_t11_stage0a.sh",
    "runner_sha256": "scripts/wmi/euf_viper_t11_stage0a.sbatch",
    "finalizer_sbatch_sha256": "scripts/wmi/euf_viper_t11_stage0a_finalize.sbatch",
    "finalizer_sha256": "scripts/bench/finalize_t11_stage0a.py",
    "authorizer_sha256": "scripts/bench/authorize_t11_stage0a.py",
    "authorization_request_executor_sha256": (
        "scripts/bench/execute_t11_stage0a_authorization_request.py"
    ),
    "validator_sha256": "scripts/bench/validate_t11_stage0a.py",
    "exec_helper_sha256": "scripts/bench/exec_t11_stage0a.py",
    "prebuilt_preparer_sha256": "scripts/bench/prepare_t11_prebuilt.py",
    "prebuilt_bundle_tool_sha256": "scripts/bench/t11_build_closure.py",
    "design_note_sha256": (
        "research-vault/02-design/2026-07-17-t11-bounded-equality-resolution-compiler.md"
    ),
    "hash_contract_sha256": (
        "research-vault/02-design/2026-07-17-t11-canonical-hash-contract.md"
    ),
    "audit_contract_sha256": (
        "research-vault/02-design/2026-07-17-t11-external-audit-receipt.md"
    ),
}


class LaunchConstructionError(RuntimeError):
    """A fail-closed launch construction error."""


def _fail(message: str) -> None:
    raise LaunchConstructionError(message)


def _canonical_json(value: object) -> bytes:
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


def _ordered_json(value: object) -> bytes:
    """Encode fields in the insertion order used by the Rust contract."""
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=False,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _canonical_path(path: Path, label: str, *, require_directory: bool = False) -> Path:
    absolute = Path(os.path.abspath(path))
    canonical = Path(os.path.realpath(absolute))
    if absolute != canonical:
        _fail(f"{label} must be canonical and nonsymlinked")
    try:
        metadata = os.stat(canonical, follow_symlinks=False)
    except OSError as error:
        _fail(f"cannot inspect {label}: {error}")
    expected = stat.S_ISDIR if require_directory else stat.S_ISREG
    if not expected(metadata.st_mode):
        _fail(f"{label} has the wrong file type")
    return canonical


def _read_stable(path: Path, label: str, maximum: int = MAX_FILE_BYTES) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        _fail(f"cannot open {label}: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            _fail(f"{label} is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                _fail(f"{label} was truncated while read")
            chunks.append(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if identity(before) != identity(after):
            _fail(f"{label} changed while read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _sha256_file(path: Path, label: str) -> str:
    return hashlib.sha256(_read_stable(path, label)).hexdigest()


def _strict_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    encoded = _read_stable(path, label)
    try:
        value = json.loads(
            encoded.decode("ascii", "strict"),
            object_pairs_hook=validator._no_duplicate_object,
            parse_constant=validator._reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, validator.ValidationError) as error:
        _fail(f"cannot decode {label}: {error}")
    if not isinstance(value, dict) or _canonical_json(value) != encoded:
        _fail(f"{label} must be one canonical JSON object")
    return value, encoded


def _run(
    executable: Path,
    arguments: Sequence[str],
    *,
    cwd: Path,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            [str(executable), *arguments],
            cwd=cwd,
            env={"HOME": "/", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        _fail(f"cannot execute {label}: {error}")
    if (
        len(completed.stdout) > MAX_TOOL_OUTPUT_BYTES
        or len(completed.stderr) > MAX_TOOL_OUTPUT_BYTES
    ):
        _fail(f"{label} output exceeds its bound")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        _fail(f"{label} failed with exit {completed.returncode}: {detail[:1000]}")
    return completed


def _version_record(path: Path, label: str) -> dict[str, str]:
    canonical = _canonical_path(path, label)
    metadata = os.stat(canonical, follow_symlinks=False)
    if metadata.st_mode & 0o111 == 0:
        _fail(f"{label} is not executable")
    completed = _run(canonical, ["--version"], cwd=Path("/"), label=f"{label} version")
    stdout = completed.stdout.decode("utf-8", "strict").strip()
    stderr = completed.stderr.decode("utf-8", "strict").strip()
    if stdout and stderr:
        _fail(f"{label} version used both stdout and stderr")
    lines = (stdout or stderr).splitlines()
    if len(lines) != 1 or not lines[0]:
        _fail(f"{label} version is not one exact line")
    return {
        "path": str(canonical),
        "sha256": _sha256_file(canonical, label),
        "version": lines[0],
    }


def _git_identity(source: Path, git: Path) -> tuple[str, str]:
    status = _run(
        git,
        ["-C", str(source), "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=Path("/"),
        label="Git status",
    ).stdout.decode("utf-8", "strict")
    if status:
        _fail("source repository must be completely clean")
    commit = _run(
        git,
        ["-C", str(source), "rev-parse", "--verify", "HEAD^{commit}"],
        cwd=Path("/"),
        label="Git commit identity",
    ).stdout.decode("ascii", "strict").strip()
    tree = _run(
        git,
        ["-C", str(source), "rev-parse", "--verify", "HEAD^{tree}"],
        cwd=Path("/"),
        label="Git tree identity",
    ).stdout.decode("ascii", "strict").strip()
    if REVISION_RE.fullmatch(commit) is None or REVISION_RE.fullmatch(tree) is None:
        _fail("Git source identity is malformed")
    return commit, tree


def _record(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(f"{label} fields differ")
    return dict(value)


def construct(args: argparse.Namespace) -> tuple[dict[str, Any], bytes]:
    source = _canonical_path(
        Path(args.source_repository), "source repository", require_directory=True
    )
    preparation_path = _canonical_path(
        Path(args.prebuilt_preparation), "prebuilt preparation"
    )
    output = Path(os.path.abspath(args.output))
    output_parent = _canonical_path(
        output.parent, "launch output parent", require_directory=True
    )
    if output.exists() or output.parent != output_parent:
        _fail("launch output must be a fresh path under a canonical parent")
    if output == source or source in output.parents:
        _fail("launch output must remain outside the source repository")

    control_paths = {
        "git": Path(args.git),
        "sbatch": Path(args.sbatch),
        "scontrol": Path(args.scontrol),
        "scancel": Path(args.scancel),
        "sacct": Path(args.sacct),
    }
    control_tools = {
        label: _version_record(path, label) for label, path in control_paths.items()
    }
    commit, tree = _git_identity(source, Path(control_tools["git"]["path"]))

    preparation, preparation_bytes = _strict_json(
        preparation_path, "prebuilt preparation"
    )
    preparation = _record(
        preparation,
        {"artifacts", "build", "elf", "schema", "smoke", "source", "status", "tools"},
        "prebuilt preparation",
    )
    if preparation.get("schema") != validator.PREBUILT_PREPARATION_SCHEMA:
        _fail("prebuilt preparation schema differs")
    source_record = _record(
        preparation.get("source"), {"commit", "tree"}, "prebuilt source"
    )
    if source_record != {"commit": commit, "tree": tree}:
        _fail("prebuilt preparation source differs from the clean checkout")
    tools = _record(
        preparation.get("tools"),
        {"bundle_tool", "cargo", "preparer", "python", "rustc"},
        "prebuilt tools",
    )
    python = _record(
        tools["python"], {"path", "sha256", "version"}, "prebuilt Python"
    )
    artifacts = _record(
        preparation.get("artifacts"),
        {
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
        },
        "prebuilt artifacts",
    )
    candidate = _record(
        artifacts["candidate"], {"bytes", "path", "sha256"}, "prebuilt candidate"
    )
    receipt = _record(
        artifacts["build_receipt"], {"path", "sha256"}, "prebuilt build receipt"
    )
    dependencies = _record(
        artifacts["dependency_inventory"],
        {"path", "sha256"},
        "prebuilt dependency inventory",
    )
    bundle = _record(
        artifacts["prebuilt_bundle"],
        {"manifest_sha256", "path", "sha256"},
        "prebuilt bundle",
    )

    launch_artifacts: dict[str, str] = {}
    for field, relative in PINNED_ARTIFACT_PATHS.items():
        artifact_path = _canonical_path(source / relative, field)
        launch_artifacts[field] = _sha256_file(artifact_path, field)

    manifest = {
        "schema": validator.LAUNCH_SCHEMA,
        "solver_revision": commit,
        "solver_source": {"commit": commit, "tree": tree},
        "target": {
            "relative_path": validator.TARGET_RELATIVE_PATH,
            "sha256": validator.TARGET_SHA256,
        },
        "baseline": {
            **validator.EXPECTED_INPUT_COUNTERS,
            "atom_map_sha256": validator.ATOM_MAP_SHA256,
            "baseline_cnf_sha256": validator.BASELINE_CNF_SHA256,
            "baseline_problem_sha256": validator.BASELINE_PROBLEM_SHA256,
        },
        "toolchain": {"python": python},
        "prebuilt_bundle": {
            "build_receipt_sha256": receipt["sha256"],
            "candidate_bytes": candidate["bytes"],
            "candidate_sha256": candidate["sha256"],
            "dependency_inventory_sha256": dependencies["sha256"],
            "manifest_sha256": bundle["manifest_sha256"],
            "path": bundle["path"],
            "schema": validator.PREBUILT_BUNDLE_SCHEMA,
            "sha256": bundle["sha256"],
            "source_commit": commit,
            "source_tree": tree,
        },
        "prebuilt_preparation": {
            "path": str(preparation_path),
            "schema": validator.PREBUILT_PREPARATION_SCHEMA,
            "sha256": hashlib.sha256(preparation_bytes).hexdigest(),
        },
        "control_tools": control_tools,
        "artifacts": launch_artifacts,
    }
    encoded = _ordered_json(manifest)
    return manifest, encoded


def _publish_validated(
    output: Path,
    encoded: bytes,
    validate: Callable[[Path, str], object],
) -> str:
    parent = output.parent
    descriptor, temporary_name = tempfile.mkstemp(prefix=".t11-launch-", dir=parent)
    temporary = Path(temporary_name)
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                _fail("short launch-manifest write")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        digest = hashlib.sha256(encoded).hexdigest()
        validate(temporary, digest)
        try:
            os.link(temporary, output, follow_symlinks=False)
        except FileExistsError:
            _fail("launch output ceased to be fresh")
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return digest
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--prebuilt-preparation", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--git", required=True)
    parser.add_argument("--sbatch", required=True)
    parser.add_argument("--scontrol", required=True)
    parser.add_argument("--scancel", required=True)
    parser.add_argument("--sacct", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        _, encoded = construct(args)
        output = Path(os.path.abspath(args.output))
        digest = _publish_validated(output, encoded, validator._validate_launch_manifest)
    except (
        LaunchConstructionError,
        OSError,
        UnicodeError,
        validator.ValidationError,
    ) as error:
        print(f"T11 launch construction rejected: {error}", file=sys.stderr)
        return 2
    print(f"t11_launch_manifest={output}")
    print(f"t11_launch_manifest_sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
