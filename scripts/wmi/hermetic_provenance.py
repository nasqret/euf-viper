#!/usr/bin/env python3
"""Create and verify fail-closed provenance for locked WMI attempts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "euf-viper.wmi-attempt-provenance.v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX_REVISION = re.compile(r"^[0-9a-f]{40,64}$")
ATTEMPT_ID = re.compile(r"^[0-9a-f]{32}$")
TOOL_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
REQUIRED_RUNTIME_TOOLS = frozenset(
    {
        "ar",
        "bash",
        "cargo",
        "cc",
        "chmod",
        "cmp",
        "curl",
        "cxx",
        "env",
        "find",
        "git",
        "mkdir",
        "python",
        "ranlib",
        "rustc",
        "sbatch",
        "sha256sum",
        "tar",
        "unzip",
    }
)
REQUIRED_EXECUTION_ENV = frozenset(
    {
        "CARGO_TARGET_DIR",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHON_FLAGS",
        "RUSTUP_HOME",
        "TMPDIR",
        "TZ",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
    }
)
REQUIRED_PARAMETERS = frozenset({"shared_corpus", "shards"})
PREPARATION_KEYS = frozenset(
    {
        "schema",
        "status",
        "attempt",
        "artifacts",
        "build_features",
        "corpus",
        "environment",
        "execution_environment",
        "feature_report",
        "hostname",
        "job",
        "paths",
        "revision",
        "runtime_tools",
        "shards",
        "solver_executables",
        "source",
        "submission_manifest_sha256",
        "viper",
    }
)

COMMON_EUF_ENV = frozenset(
    {
        "EUF_VIPER_ATTEMPT_ID",
        "EUF_VIPER_ATTEMPT_ROOT",
        "EUF_VIPER_CHECKOUT",
        "EUF_VIPER_EXPECTED_REVISION",
        "EUF_VIPER_PYTHON",
        "EUF_VIPER_PYTHON_SHA256",
        "EUF_VIPER_PROVENANCE_HELPER_SHA256",
        "EUF_VIPER_SHA256SUM",
        "EUF_VIPER_SUBMISSION_MANIFEST",
        "EUF_VIPER_SUBMISSION_MANIFEST_SHA256",
    }
)
STAGE_EUF_ENV = {
    "prepare": frozenset(
        {
            "EUF_VIPER_LOCKED_SHARDS",
            "EUF_VIPER_SHARED_CORPUS",
        }
    ),
    "shard": frozenset(
        {
            "EUF_VIPER_CORPUS_KIND",
            "EUF_VIPER_PREPARE_JOB_ID",
        }
    ),
    "audit": frozenset(
        {
            "EUF_VIPER_LOCKED_SHARDS",
            "EUF_VIPER_PREPARE_JOB_ID",
        }
    ),
}
SUBMIT_EUF_ENV = frozenset(
    {
        "EUF_VIPER_LOCKED_MAX_ACTIVE",
        "EUF_VIPER_LOCKED_SHARDS",
        "EUF_VIPER_SHARED_CORPUS",
        "EUF_VIPER_WMI_CAMPAIGN_ROOT",
        "EUF_VIPER_WMI_HOST",
    }
)

FORBIDDEN_EXACT_ENV = frozenset(
    {
        "AR",
        "BASH_ENV",
        "CC",
        "CDPATH",
        "CFLAGS",
        "CPP",
        "CPPFLAGS",
        "CXX",
        "CXXFLAGS",
        "ENV",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_SYSTEM",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
        "LD",
        "LDFLAGS",
        "LIBCLANG_PATH",
        "LIBRARY_PATH",
        "MFLAGS",
        "MAKEFLAGS",
        "NM",
        "OBJCOPY",
        "OBJDUMP",
        "PYTHONBREAKPOINT",
        "PYTHONEXECUTABLE",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONSAFEPATH",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONWARNINGS",
        "RANLIB",
        "RUSTC",
        "RUSTC_BOOTSTRAP",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOC",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
        "SDKROOT",
        "STRIP",
    }
)
FORBIDDEN_PREFIX_ENV = (
    "BINDGEN_",
    "CARGO_",
    "CMAKE_",
    "CONAN_",
    "DYLD_",
    "GIT_CONFIG_",
    "LD_",
    "MESON_",
    "NINJA_",
    "PKG_CONFIG",
    "RUSTFLAGS_",
    "VCPKG_",
)


class ProvenanceError(ValueError):
    """Raised when an attempt is not hermetic enough to execute."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_regular_nofollow(path: Path, label: str) -> tuple[bytes, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise ProvenanceError(f"cannot open {label} {path} without symlinks: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ProvenanceError(f"{label} is not a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    data = b"".join(chunks)
    if identity_before != identity_after or len(data) != after.st_size:
        raise ProvenanceError(f"{label} changed while it was read: {path}")
    return data, after


def read_regular_beneath(
    root: Path, relative: str, label: str
) -> tuple[bytes, os.stat_result]:
    components = Path(relative).parts
    if not components or any(component in {"", ".", ".."} for component in components):
        raise ProvenanceError(f"invalid relative {label} path: {relative!r}")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in components[:-1]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        file_descriptor = os.open(
            components[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor
        )
    except OSError as error:
        raise ProvenanceError(
            f"cannot open {label} {relative!r} beneath {root}: {error}"
        ) from error
    finally:
        os.close(descriptor)
    try:
        before = os.fstat(file_descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ProvenanceError(f"{label} is not a regular file: {relative}")
        chunks: list[bytes] = []
        while True:
            block = os.read(file_descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(file_descriptor)
    finally:
        os.close(file_descriptor)
    data = b"".join(chunks)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) or len(data) != after.st_size:
        raise ProvenanceError(f"{label} changed while it was read: {relative}")
    return data, after


def sha256_file(path: Path) -> str:
    data, _ = read_regular_nofollow(path, "runtime file")
    return sha256_bytes(data)


def strict_json_load_bytes(data: bytes, path: Path) -> dict[str, Any]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ProvenanceError(f"duplicate JSON key {key!r} in {path}")
            value[key] = item
        return value

    try:
        value = json.loads(data, object_pairs_hook=object_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ProvenanceError(f"cannot read provenance manifest {path}: {error}") from error
    if type(value) is not dict:
        raise ProvenanceError("provenance manifest must be a JSON object")
    return value


def run_git(repository: Path, arguments: Iterable[str], *, binary: str = "git") -> bytes:
    environment = {
        "HOME": os.environ.get("HOME", ""),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", os.defpath),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }
    completed = subprocess.run(
        [binary, "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        env=environment,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode("utf-8", "replace").strip()
        raise ProvenanceError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout


def require_private_attempt_root(path: Path) -> Path:
    absolute = path.absolute()
    resolved = path.resolve(strict=True)
    if absolute != resolved:
        raise ProvenanceError(f"attempt root must not contain symlinks: {path}")
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ProvenanceError(f"attempt root is not a directory: {path}")
    if metadata.st_uid != os.getuid():
        raise ProvenanceError(f"attempt root is not owned by uid {os.getuid()}: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ProvenanceError(f"attempt root must have mode 0700: {path}")
    return resolved


def git_blob_oid(data: bytes, object_format: str) -> str:
    framed = f"blob {len(data)}\0".encode("ascii") + data
    if object_format == "sha1":
        return hashlib.sha1(framed).hexdigest()
    if object_format == "sha256":
        return hashlib.sha256(framed).hexdigest()
    raise ProvenanceError(f"unsupported Git object format {object_format!r}")


def repository_manifest(repository: Path, revision: str, *, git_binary: str) -> dict[str, Any]:
    root = repository.resolve(strict=True)
    if repository.absolute() != root:
        raise ProvenanceError(f"checkout path must not contain symlinks: {repository}")
    actual_revision = run_git(root, ["rev-parse", "HEAD"], binary=git_binary).decode().strip()
    if actual_revision != revision:
        raise ProvenanceError(
            f"checkout revision mismatch: expected {revision}, got {actual_revision}"
        )
    object_format = (
        run_git(root, ["rev-parse", "--show-object-format"], binary=git_binary)
        .decode()
        .strip()
    )
    tree = run_git(root, ["rev-parse", "HEAD^{tree}"], binary=git_binary).decode().strip()

    index_tags = run_git(root, ["ls-files", "-v", "-z"], binary=git_binary)
    abnormal: list[str] = []
    for record in index_tags.split(b"\0"):
        if not record:
            continue
        if len(record) < 3 or record[1:2] != b" " or record[:1] != b"H":
            abnormal.append(record.decode("utf-8", "replace"))
    if abnormal:
        raise ProvenanceError(
            "checkout contains skip-worktree, assume-unchanged, or abnormal index entries: "
            + ", ".join(abnormal[:8])
        )

    status = run_git(
        root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching"],
        binary=git_binary,
    )
    if status:
        entries = [
            record.decode("utf-8", "replace")
            for record in status.split(b"\0")
            if record
        ]
        raise ProvenanceError(
            "checkout contains tracked, untracked, or ignored execution influences: "
            + ", ".join(entries[:8])
        )

    staged = run_git(root, ["ls-files", "-s", "-z"], binary=git_binary)
    files: list[dict[str, Any]] = []
    for record in staged.split(b"\0"):
        if not record:
            continue
        try:
            prefix, raw_path = record.split(b"\t", 1)
            raw_mode, raw_oid, raw_stage = prefix.split(b" ")
            relative = raw_path.decode("utf-8")
        except (ValueError, UnicodeError) as error:
            raise ProvenanceError("malformed or non-UTF-8 Git index record") from error
        mode = raw_mode.decode("ascii")
        oid = raw_oid.decode("ascii")
        if raw_stage != b"0" or mode not in {"100644", "100755"}:
            raise ProvenanceError(f"unsupported index entry {mode} {relative}")
        data, metadata = read_regular_beneath(root, relative, "tracked source")
        if git_blob_oid(data, object_format) != oid:
            raise ProvenanceError(f"working bytes differ from Git blob for {relative}")
        executable = bool(stat.S_IMODE(metadata.st_mode) & 0o111)
        if executable != (mode == "100755"):
            raise ProvenanceError(f"working executable mode differs from Git for {relative}")
        files.append(
            {
                "bytes": len(data),
                "git_blob": oid,
                "mode": mode,
                "path": relative,
                "sha256": sha256_bytes(data),
            }
        )
    files.sort(key=lambda item: item["path"])
    return {
        "object_format": object_format,
        "root": str(root),
        "source_blob_count": len(files),
        "source_blobs": files,
        "source_blobs_sha256": sha256_bytes(canonical_bytes(files)),
        "tree": tree,
    }


def runtime_tools(values: list[str]) -> dict[str, dict[str, Any]]:
    tools: dict[str, dict[str, Any]] = {}
    for value in values:
        name, separator, raw_path = value.partition("=")
        if not separator or not TOOL_NAME.fullmatch(name) or name in tools:
            raise ProvenanceError(f"invalid or duplicate --tool binding {value!r}")
        path = Path(raw_path)
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
            raise ProvenanceError(f"runtime tool is not an executable regular file: {path}")
        data, stable_metadata = read_regular_nofollow(resolved, "runtime tool")
        if (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ) != (
            stable_metadata.st_dev,
            stable_metadata.st_ino,
            stable_metadata.st_size,
            stable_metadata.st_mtime_ns,
            stable_metadata.st_ctime_ns,
        ):
            raise ProvenanceError(f"runtime tool changed while it was inspected: {path}")
        tools[name] = {
            "path": str(path.absolute()),
            "realpath": str(resolved),
            "sha256": sha256_bytes(data),
            "bytes": stable_metadata.st_size,
        }
    if set(tools) != REQUIRED_RUNTIME_TOOLS:
        raise ProvenanceError(
            "runtime tool bindings differ: "
            f"expected {sorted(REQUIRED_RUNTIME_TOOLS)!r}, got {sorted(tools)!r}"
        )
    return dict(sorted(tools.items()))


def parse_bindings(values: list[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        name, separator, item = value.partition("=")
        if not separator or not name or name in result:
            raise ProvenanceError(f"invalid or duplicate {label} binding {value!r}")
        result[name] = item
    return dict(sorted(result.items()))


def environment_violations(
    values: dict[str, str] | os._Environ[str], allowed_euf: frozenset[str]
) -> list[str]:
    violations: list[str] = []
    for name in values:
        if name in FORBIDDEN_EXACT_ENV or any(
            name.startswith(prefix) for prefix in FORBIDDEN_PREFIX_ENV
        ):
            violations.append(name)
        if name.startswith("EUF_VIPER_") and name not in allowed_euf:
            violations.append(name)
    return sorted(set(violations))


def audit_environment(stage: str, environment: dict[str, str] | None = None) -> dict[str, str]:
    values = os.environ if environment is None else environment
    allowed_euf = COMMON_EUF_ENV | STAGE_EUF_ENV[stage]
    violations = environment_violations(values, allowed_euf)
    if violations:
        raise ProvenanceError(
            "ambient execution controls are forbidden: " + ", ".join(sorted(set(violations)))
        )
    missing = sorted(name for name in allowed_euf if name not in values)
    if missing:
        raise ProvenanceError("required receipt-bound environment is missing: " + ", ".join(missing))
    return {name: values[name] for name in sorted(allowed_euf)}


def audit_submit_environment(environment: dict[str, str] | None = None) -> dict[str, str]:
    values = os.environ if environment is None else environment
    violations = environment_violations(values, SUBMIT_EUF_ENV)
    if violations:
        raise ProvenanceError(
            "ambient submitter controls are forbidden: " + ", ".join(violations)
        )
    return {name: values[name] for name in sorted(SUBMIT_EUF_ENV) if name in values}


def atomic_create(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(canonical_bytes(payload))
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def manifest_summary(
    path: Path, payload: dict[str, Any], *, manifest_sha256: str | None = None
) -> dict[str, Any]:
    repository = payload["repository"]
    helper = next(
        (
            record
            for record in repository["source_blobs"]
            if record["path"] == "scripts/wmi/hermetic_provenance.py"
        ),
        None,
    )
    if helper is None:
        raise ProvenanceError("source manifest omits hermetic_provenance.py")
    return {
        "attempt": payload["attempt"],
        "manifest": str(path.resolve(strict=True)),
        "manifest_sha256": manifest_sha256 or sha256_file(path),
        "revision": payload["revision"],
        "runtime_tools": payload["runtime_tools"],
        "provenance_helper_sha256": helper["sha256"],
        "source_blob_count": repository["source_blob_count"],
        "source_blobs_sha256": repository["source_blobs_sha256"],
        "source_tree": repository["tree"],
    }


def create_manifest(args: argparse.Namespace) -> dict[str, Any]:
    if not ATTEMPT_ID.fullmatch(args.attempt_id):
        raise ProvenanceError("attempt id must be 32 lowercase hexadecimal characters")
    if not HEX_REVISION.fullmatch(args.revision):
        raise ProvenanceError("revision must be a full lowercase hexadecimal Git object id")
    attempt_root = require_private_attempt_root(args.attempt_root)
    checkout = args.checkout.resolve(strict=True)
    try:
        checkout.relative_to(attempt_root)
    except ValueError as error:
        raise ProvenanceError("checkout must be inside the private attempt root") from error
    tools = runtime_tools(args.tool)
    git_tool = tools.get("git")
    if git_tool is None:
        raise ProvenanceError("runtime tools must bind git")
    repository = repository_manifest(
        checkout, args.revision, git_binary=git_tool["realpath"]
    )
    execution_environment = parse_bindings(args.execution_env, "execution environment")
    if set(execution_environment) != REQUIRED_EXECUTION_ENV:
        raise ProvenanceError(
            "execution environment bindings differ: "
            f"expected {sorted(REQUIRED_EXECUTION_ENV)!r}, "
            f"got {sorted(execution_environment)!r}"
        )
    parameters = parse_bindings(args.parameter, "parameter")
    if set(parameters) != REQUIRED_PARAMETERS:
        raise ProvenanceError(
            "parameter bindings differ: "
            f"expected {sorted(REQUIRED_PARAMETERS)!r}, got {sorted(parameters)!r}"
        )
    payload = {
        "schema": SCHEMA,
        "attempt": {
            "checkout": str(checkout),
            "id": args.attempt_id,
            "root": str(attempt_root),
        },
        "execution_environment": execution_environment,
        "parameters": parameters,
        "repository": repository,
        "revision": args.revision,
        "runtime_tools": tools,
    }
    atomic_create(args.out, payload)
    return manifest_summary(args.out, payload)


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ProvenanceError(
            f"{label} keys differ: expected {sorted(expected)!r}, got {sorted(value)!r}"
        )


def verify_manifest(args: argparse.Namespace) -> dict[str, Any]:
    if not HEX64.fullmatch(args.expected_sha256):
        raise ProvenanceError("expected manifest SHA-256 is malformed")
    manifest_bytes, _ = read_regular_nofollow(args.manifest, "submission manifest")
    if sha256_bytes(manifest_bytes) != args.expected_sha256:
        raise ProvenanceError("submission provenance manifest SHA-256 mismatch")
    payload = strict_json_load_bytes(manifest_bytes, args.manifest)
    require_exact_keys(
        payload,
        {
            "schema",
            "attempt",
            "execution_environment",
            "parameters",
            "repository",
            "revision",
            "runtime_tools",
        },
        "manifest",
    )
    if payload["schema"] != SCHEMA:
        raise ProvenanceError(f"unsupported provenance schema {payload['schema']!r}")
    if not HEX_REVISION.fullmatch(payload["revision"]):
        raise ProvenanceError("manifest revision is malformed")
    bound_environment = audit_environment(args.stage)
    attempt = payload["attempt"]
    if type(attempt) is not dict:
        raise ProvenanceError("attempt binding must be an object")
    require_exact_keys(attempt, {"checkout", "id", "root"}, "attempt")
    if not ATTEMPT_ID.fullmatch(attempt["id"]):
        raise ProvenanceError("manifest attempt id is malformed")
    if type(payload["execution_environment"]) is not dict or set(
        payload["execution_environment"]
    ) != REQUIRED_EXECUTION_ENV:
        raise ProvenanceError("manifest execution environment bindings differ")
    if type(payload["parameters"]) is not dict or set(payload["parameters"]) != REQUIRED_PARAMETERS:
        raise ProvenanceError("manifest parameter bindings differ")
    if type(payload["runtime_tools"]) is not dict or set(
        payload["runtime_tools"]
    ) != REQUIRED_RUNTIME_TOOLS:
        raise ProvenanceError("manifest runtime tool bindings differ")
    expected_attempt = {
        "checkout": bound_environment["EUF_VIPER_CHECKOUT"],
        "id": bound_environment["EUF_VIPER_ATTEMPT_ID"],
        "root": bound_environment["EUF_VIPER_ATTEMPT_ROOT"],
    }
    if attempt != expected_attempt:
        raise ProvenanceError("attempt paths or identity differ from the receipt-bound environment")
    if payload["revision"] != bound_environment["EUF_VIPER_EXPECTED_REVISION"]:
        raise ProvenanceError("manifest revision differs from the receipt-bound environment")
    if str(args.manifest.resolve(strict=True)) != bound_environment[
        "EUF_VIPER_SUBMISSION_MANIFEST"
    ]:
        raise ProvenanceError("manifest realpath differs from the receipt-bound environment")
    if args.expected_sha256 != bound_environment[
        "EUF_VIPER_SUBMISSION_MANIFEST_SHA256"
    ]:
        raise ProvenanceError("manifest hash differs from the receipt-bound environment")
    if str(Path(bound_environment["EUF_VIPER_PYTHON"]).resolve(strict=True)) != payload[
        "runtime_tools"
    ]["python"]["realpath"]:
        raise ProvenanceError("Python runtime differs from the submission manifest")
    if bound_environment["EUF_VIPER_PYTHON_SHA256"] != payload["runtime_tools"][
        "python"
    ]["sha256"]:
        raise ProvenanceError("Python SHA-256 differs from the submission manifest")
    if str(Path(bound_environment["EUF_VIPER_SHA256SUM"]).resolve(strict=True)) != payload[
        "runtime_tools"
    ]["sha256sum"]["realpath"]:
        raise ProvenanceError("sha256sum runtime differs from the submission manifest")
    if bound_environment["EUF_VIPER_PROVENANCE_HELPER_SHA256"] != manifest_summary(
        args.manifest, payload, manifest_sha256=args.expected_sha256
    )["provenance_helper_sha256"]:
        raise ProvenanceError("provenance helper SHA-256 differs from the source manifest")

    attempt_root = require_private_attempt_root(Path(attempt["root"]))
    checkout = Path(attempt["checkout"]).resolve(strict=True)
    try:
        checkout.relative_to(attempt_root)
    except ValueError as error:
        raise ProvenanceError("verified checkout escaped the private attempt root") from error
    tools = runtime_tools(
        [f"{name}={record['path']}" for name, record in payload["runtime_tools"].items()]
    )
    if tools != payload["runtime_tools"]:
        raise ProvenanceError("runtime realpath, size, or SHA-256 drifted after submission")
    repository = repository_manifest(
        checkout,
        payload["revision"],
        git_binary=tools["git"]["realpath"],
    )
    if repository != payload["repository"]:
        raise ProvenanceError("source path, tree, blobs, modes, or hashes drifted after submission")
    return {
        **manifest_summary(
            args.manifest, payload, manifest_sha256=args.expected_sha256
        ),
        "environment": bound_environment,
        "execution_environment": payload["execution_environment"],
        "parameters": payload["parameters"],
        "stage": args.stage,
    }


def verify_bound_executable(record: Any, label: str) -> dict[str, Any]:
    if type(record) is not dict:
        raise ProvenanceError(f"{label} binding must be an object")
    require_exact_keys(record, {"path", "realpath", "sha256", "bytes"}, label)
    path = Path(record["path"])
    resolved = path.resolve(strict=True)
    if str(resolved) != record["realpath"]:
        raise ProvenanceError(f"{label} realpath drifted")
    data, metadata = read_regular_nofollow(resolved, label)
    if not os.access(resolved, os.X_OK):
        raise ProvenanceError(f"{label} is no longer executable")
    if record["bytes"] != metadata.st_size or record["sha256"] != sha256_bytes(data):
        raise ProvenanceError(f"{label} size or SHA-256 drifted")
    return record


def verify_bound_artifact(record: Any, root: Path, label: str) -> dict[str, Any]:
    if type(record) is not dict:
        raise ProvenanceError(f"{label} binding must be an object")
    require_exact_keys(record, {"path", "sha256"}, label)
    path = Path(record["path"])
    resolved = path.resolve(strict=True)
    if path.absolute() != resolved:
        raise ProvenanceError(f"{label} path contains a symlink")
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ProvenanceError(f"{label} escaped the locked run root") from error
    data, _ = read_regular_nofollow(resolved, label)
    if record["sha256"] != sha256_bytes(data):
        raise ProvenanceError(f"{label} SHA-256 drifted")
    return record


def verify_preparation_receipt(args: argparse.Namespace) -> dict[str, Any]:
    receipt_bytes, _ = read_regular_nofollow(args.receipt, "preparation receipt")
    value = strict_json_load_bytes(receipt_bytes, args.receipt)
    if canonical_bytes(value) != receipt_bytes:
        raise ProvenanceError("preparation receipt is not canonical JSON")
    require_exact_keys(value, set(PREPARATION_KEYS), "preparation receipt")
    if (
        value["schema"] != "euf-viper.locked-p0-preparation.v2"
        or value["status"] != "prepared"
    ):
        raise ProvenanceError("invalid preparation receipt schema or status")
    provenance = strict_json_load_bytes(args.provenance.encode("utf-8"), Path("<provenance>"))
    run_root = args.run_root.resolve(strict=True)
    expected = {
        "attempt": provenance["attempt"],
        "revision": provenance["revision"],
        "submission_manifest_sha256": provenance["manifest_sha256"],
        "environment": provenance["environment"],
        "execution_environment": provenance["execution_environment"],
        "runtime_tools": provenance["runtime_tools"],
    }
    for name, expected_value in expected.items():
        if value[name] != expected_value:
            raise ProvenanceError(f"preparation receipt {name} mismatch")
    if type(value["paths"]) is not dict:
        raise ProvenanceError("preparation receipt paths must be an object")
    require_exact_keys(
        value["paths"], {"checkout", "run_root", "submission_manifest"}, "paths"
    )
    if value["paths"]["run_root"] != str(run_root):
        raise ProvenanceError("preparation receipt run root mismatch")
    if value["paths"]["checkout"] != provenance["attempt"]["checkout"]:
        raise ProvenanceError("preparation receipt checkout mismatch")
    if value["paths"]["submission_manifest"] != provenance["manifest"]:
        raise ProvenanceError("preparation receipt manifest path mismatch")
    if type(value["job"]) is not dict:
        raise ProvenanceError("preparation receipt job must be an object")
    require_exact_keys(value["job"], {"id", "submit_directory"}, "preparation job")
    if value["job"]["id"] != args.prepare_job:
        raise ProvenanceError("preparation receipt job mismatch")
    if value["shards"] != int(provenance["parameters"]["shards"]):
        raise ProvenanceError("preparation receipt shard count mismatch")
    if value["build_features"] != [
        "certificates",
        "default",
        "finite-symmetry",
        "production-evidence",
    ]:
        raise ProvenanceError("preparation receipt lacks the exact locked evidence features")
    source = value["source"]
    if source != {
        "blob_count": provenance["source_blob_count"],
        "blobs_sha256": provenance["source_blobs_sha256"],
        "tree": provenance["source_tree"],
    }:
        raise ProvenanceError("preparation receipt source summary mismatch")
    if type(value["artifacts"]) is not dict or set(value["artifacts"]) != {
        "solver-config.json",
        "taxonomy/full.jsonl",
        "taxonomy/full-split.json",
        "taxonomy/official.jsonl",
        "taxonomy/official-split.json",
        "locks/full-parent.json",
        "locks/official-parent.json",
    }:
        raise ProvenanceError("preparation receipt artifact set differs")
    for name, record in value["artifacts"].items():
        verify_bound_artifact(record, run_root, f"preparation artifact {name}")
    corpus = value["corpus"]
    if type(corpus) is not dict:
        raise ProvenanceError("preparation corpus binding must be an object")
    require_exact_keys(corpus, {"full_manifest", "official_manifest", "root"}, "corpus")
    for name in ("full_manifest", "official_manifest"):
        record = corpus[name]
        if type(record) is not dict:
            raise ProvenanceError(f"corpus {name} must be an object")
        require_exact_keys(record, {"path", "sha256"}, f"corpus {name}")
        data, _ = read_regular_nofollow(Path(record["path"]), f"corpus {name}")
        if sha256_bytes(data) != record["sha256"]:
            raise ProvenanceError(f"corpus {name} SHA-256 drifted")
    verify_bound_executable(value["feature_report"], "feature report")
    verify_bound_executable(value["viper"], "euf-viper")
    if type(value["solver_executables"]) is not dict or set(
        value["solver_executables"]
    ) != {"euf-viper", "z3-default", "z3-sat-euf", "cvc5", "yices2", "opensmt"}:
        raise ProvenanceError("solver executable binding set differs")
    for name, record in value["solver_executables"].items():
        verify_bound_executable(record, f"solver {name}")
    return {
        "attempt": value["attempt"],
        "receipt": str(args.receipt.resolve(strict=True)),
        "receipt_sha256": sha256_bytes(receipt_bytes),
        "revision": value["revision"],
        "run_root": str(run_root),
        "status": "accepted",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--attempt-id", required=True)
    create.add_argument("--attempt-root", type=Path, required=True)
    create.add_argument("--checkout", type=Path, required=True)
    create.add_argument("--revision", required=True)
    create.add_argument("--tool", action="append", default=[], required=True)
    create.add_argument("--execution-env", action="append", default=[])
    create.add_argument("--parameter", action="append", default=[])
    create.add_argument("--out", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--expected-sha256", required=True)
    verify.add_argument("--stage", choices=tuple(STAGE_EUF_ENV), required=True)

    prepare = subparsers.add_parser("verify-preparation-receipt")
    prepare.add_argument("--receipt", type=Path, required=True)
    prepare.add_argument("--provenance", required=True)
    prepare.add_argument("--run-root", type=Path, required=True)
    prepare.add_argument("--prepare-job", type=int, required=True)

    subparsers.add_parser("audit-submit-environment")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "create":
            result = create_manifest(args)
        elif args.command == "verify":
            result = verify_manifest(args)
        elif args.command == "verify-preparation-receipt":
            result = verify_preparation_receipt(args)
        else:
            result = {"environment": audit_submit_environment(), "status": "accepted"}
    except (OSError, ProvenanceError, KeyError, TypeError) as error:
        parser.exit(2, f"hermetic provenance rejected: {error}\n")
    print(canonical_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
