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


SCHEMA = "euf-viper.wmi-attempt-provenance.v2"
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
        "ldd",
        "mkdir",
        "python",
        "ranlib",
        "rustc",
        "unshare",
        "sbatch",
        "sha256sum",
        "strace",
        "tar",
        "unzip",
    }
)
REQUIRED_EXECUTION_ENV = frozenset(
    {
        "CARGO_TARGET_DIR",
        "CARGO_HOME",
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
        "sealed_build",
        "execution_closure",
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
            "EUF_VIPER_PREPARE_RECEIPT_SHA256",
        }
    ),
    "audit": frozenset(
        {
            "EUF_VIPER_LOCKED_SHARDS",
            "EUF_VIPER_PREPARE_JOB_ID",
            "EUF_VIPER_PREPARE_RECEIPT_SHA256",
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
    source_hashes = {
        record["path"]: record["sha256"] for record in repository["source_blobs"]
    }
    required_helpers = {
        "attestor_helper_sha256": "scripts/wmi/attest_sealed_build.py",
        "provenance_helper_sha256": "scripts/wmi/hermetic_provenance.py",
        "sealed_build_helper_sha256": "scripts/wmi/sealed_linux_build.py",
        "execution_closure_helper_sha256": "scripts/wmi/execution_closure.py",
    }
    missing = sorted(path for path in required_helpers.values() if path not in source_hashes)
    if missing:
        raise ProvenanceError("source manifest omits provenance helpers: " + ", ".join(missing))
    return {
        "attempt": payload["attempt"],
        "manifest": str(path.resolve(strict=True)),
        "manifest_sha256": manifest_sha256 or sha256_file(path),
        "revision": payload["revision"],
        "runtime_tools": payload["runtime_tools"],
        **{name: source_hashes[path] for name, path in required_helpers.items()},
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


def verify_preparation_environment_compatibility(
    preparation_environment: Any,
    provenance: Any,
    *,
    prepare_job: int,
    shards: int,
    receipt_sha256: str,
) -> None:
    """Verify a prepare-stage receipt against one shard or audit-stage binding."""

    if type(prepare_job) is not int or prepare_job < 1:
        raise ProvenanceError("preparation job binding must be a positive integer")
    if type(shards) is not int or shards < 1:
        raise ProvenanceError("preparation shard binding must be a positive integer")
    if type(receipt_sha256) is not str or not HEX64.fullmatch(receipt_sha256):
        raise ProvenanceError("preparation receipt SHA-256 binding is malformed")
    if type(provenance) is not dict:
        raise ProvenanceError("current provenance must be an object")
    stage = provenance.get("stage")
    if stage not in {"shard", "audit"}:
        raise ProvenanceError(
            "preparation receipts may only be consumed at shard or audit stage"
        )
    current_environment = provenance.get("environment")
    if type(current_environment) is not dict or any(
        type(name) is not str or type(value) is not str
        for name, value in current_environment.items()
    ):
        raise ProvenanceError("current provenance environment must bind strings")
    if type(preparation_environment) is not dict or any(
        type(name) is not str or type(value) is not str
        for name, value in preparation_environment.items()
    ):
        raise ProvenanceError("preparation receipt environment must bind strings")
    parameters = provenance.get("parameters")
    if type(parameters) is not dict:
        raise ProvenanceError("current provenance parameters must be an object")
    require_exact_keys(parameters, set(REQUIRED_PARAMETERS), "current parameters")
    if any(type(value) is not str or not value for value in parameters.values()):
        raise ProvenanceError("current provenance parameters must bind strings")

    require_exact_keys(
        preparation_environment,
        set(COMMON_EUF_ENV | STAGE_EUF_ENV["prepare"]),
        "preparation receipt environment",
    )
    require_exact_keys(
        current_environment,
        set(COMMON_EUF_ENV | STAGE_EUF_ENV[stage]),
        f"{stage} provenance environment",
    )
    for name in sorted(COMMON_EUF_ENV):
        if preparation_environment[name] != current_environment[name]:
            raise ProvenanceError(
                f"preparation and {stage} common environment binding {name} differs"
            )

    shard_text = str(shards)
    if parameters["shards"] != shard_text:
        raise ProvenanceError("provenance shard parameter disagrees with receipt")
    if preparation_environment["EUF_VIPER_LOCKED_SHARDS"] != shard_text:
        raise ProvenanceError("prepare-stage shard binding disagrees with receipt")
    if (
        preparation_environment["EUF_VIPER_SHARED_CORPUS"]
        != parameters["shared_corpus"]
    ):
        raise ProvenanceError(
            "prepare-stage shared corpus disagrees with provenance parameter"
        )
    if current_environment["EUF_VIPER_PREPARE_JOB_ID"] != str(prepare_job):
        raise ProvenanceError(f"{stage}-stage prepare job binding disagrees")
    if (
        current_environment["EUF_VIPER_PREPARE_RECEIPT_SHA256"]
        != receipt_sha256
    ):
        raise ProvenanceError(f"{stage}-stage preparation receipt hash disagrees")
    if stage == "audit":
        if current_environment["EUF_VIPER_LOCKED_SHARDS"] != shard_text:
            raise ProvenanceError("audit-stage shard binding disagrees with receipt")
    elif current_environment["EUF_VIPER_CORPUS_KIND"] not in {"full", "official"}:
        raise ProvenanceError("shard-stage corpus kind must be full or official")


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
    if not HEX64.fullmatch(args.expected_sha256):
        raise ProvenanceError("expected preparation receipt SHA-256 is malformed")
    if sha256_bytes(receipt_bytes) != args.expected_sha256:
        raise ProvenanceError("preparation receipt SHA-256 differs from external binding")
    value = strict_json_load_bytes(receipt_bytes, args.receipt)
    if canonical_bytes(value) != receipt_bytes:
        raise ProvenanceError("preparation receipt is not canonical JSON")
    require_exact_keys(value, set(PREPARATION_KEYS), "preparation receipt")
    if (
        value["schema"] != "euf-viper.locked-p0-preparation.v3"
        or value["status"] != "prepared"
    ):
        raise ProvenanceError("invalid preparation receipt schema or status")
    provenance = strict_json_load_bytes(args.provenance.encode("utf-8"), Path("<provenance>"))
    run_root = args.run_root.resolve(strict=True)
    expected = {
        "attempt": provenance["attempt"],
        "revision": provenance["revision"],
        "submission_manifest_sha256": provenance["manifest_sha256"],
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
    if type(value["shards"]) is not int or value["shards"] < 1:
        raise ProvenanceError("preparation receipt shard count is invalid")
    verify_preparation_environment_compatibility(
        value["environment"],
        provenance,
        prepare_job=args.prepare_job,
        shards=value["shards"],
        receipt_sha256=args.expected_sha256,
    )
    if value["build_features"] != [
        "certificates",
        "default",
        "finite-symmetry",
        "production-evidence",
    ]:
        raise ProvenanceError("preparation receipt lacks the exact locked evidence features")
    verify_bound_executable(value["feature_report"], "feature report")
    verify_bound_executable(value["viper"], "euf-viper")
    source = value["source"]
    if type(source) is not dict:
        raise ProvenanceError("preparation receipt source summary must be an object")
    require_exact_keys(
        source,
        {
            "blob_count",
            "blobs_sha256",
            "tree",
            "snapshot_manifest_sha256",
            "build_execution_closure_sha256",
        },
        "preparation source summary",
    )
    if source["blob_count"] != provenance[
        "source_blob_count"
    ] or source["blobs_sha256"] != provenance["source_blobs_sha256"] or source[
        "tree"
    ] != provenance["source_tree"]:
        raise ProvenanceError("preparation receipt source summary mismatch")
    sealed_build = value["sealed_build"]
    if type(sealed_build) is not dict:
        raise ProvenanceError("sealed build binding must be an object")
    require_exact_keys(
        sealed_build,
        {
            "attestation_path",
            "attestation_sha256",
            "path",
            "sha256",
            "source_snapshot_manifest_sha256",
            "build_execution_closure_sha256",
            "receipt_path",
            "receipt_sha256",
        },
        "sealed build",
    )
    sealed_bytes, _ = read_regular_nofollow(Path(sealed_build["path"]), "sealed build manifest")
    if sha256_bytes(sealed_bytes) != sealed_build["sha256"]:
        raise ProvenanceError("sealed build manifest SHA-256 drifted")
    sealed_value = strict_json_load_bytes(sealed_bytes, Path(sealed_build["path"]))
    if canonical_bytes(sealed_value) != sealed_bytes:
        raise ProvenanceError("sealed build manifest is not canonical JSON")
    require_exact_keys(
        sealed_value,
        {
            "schema",
            "status",
            "artifacts",
            "build_execution_closure",
            "build_execution_closure_sha256",
            "build_execution_verification",
            "revision",
            "source_snapshot",
            "source_snapshot_manifest_sha256",
            "source_tree",
            "toolchain",
        },
        "sealed build manifest",
    )
    if (
        sealed_value.get("schema") != "euf-viper.sealed-linux-build.v3"
        or sealed_value.get("status") != "built"
        or sealed_value.get("revision") != value["revision"]
        or sealed_value.get("source_tree") != provenance["source_tree"]
        or sealed_value.get("source_snapshot_manifest_sha256")
        != sealed_build["source_snapshot_manifest_sha256"]
        or sealed_value.get("build_execution_closure_sha256")
        != sealed_build["build_execution_closure_sha256"]
    ):
        raise ProvenanceError("sealed build manifest binding mismatch")
    if (
        source["snapshot_manifest_sha256"]
        != sealed_build["source_snapshot_manifest_sha256"]
        or source["build_execution_closure_sha256"]
        != sealed_build["build_execution_closure_sha256"]
        or sha256_bytes(canonical_bytes(sealed_value["source_snapshot"]))
        != sealed_build["source_snapshot_manifest_sha256"]
        or sha256_bytes(canonical_bytes(sealed_value["build_execution_closure"]))
        != sealed_build["build_execution_closure_sha256"]
    ):
        raise ProvenanceError("sealed build embedded manifest hash mismatch")
    sealed_toolchain = sealed_value["toolchain"]
    if (
        type(sealed_toolchain) is not dict
        or set(sealed_toolchain) != {"cargo", "rustc"}
        or any(type(item) is not str or not item for item in sealed_toolchain.values())
    ):
        raise ProvenanceError("sealed build toolchain binding differs")
    build_verification = sealed_value["build_execution_verification"]
    require_exact_keys(
        build_verification,
        {
            "actual_trace_sha256",
            "canonical_trace_sha256",
            "external_directory_count",
            "external_input_count",
            "status",
            "unexpected_external_inputs",
            "virtual_paths",
        },
        "sealed build execution verification",
    )
    if (
        build_verification["status"] != "accepted"
        or build_verification["unexpected_external_inputs"] != []
        or build_verification["external_input_count"]
        != len(sealed_value["build_execution_closure"].get("external_inputs", []))
        or build_verification["external_directory_count"]
        != len(
            sealed_value["build_execution_closure"].get(
                "external_directories", []
            )
        )
    ):
        raise ProvenanceError("sealed build execution verification differs")
    sealed_artifacts = sealed_value["artifacts"]
    if type(sealed_artifacts) is not dict or set(sealed_artifacts) != {
        "euf-viper",
        "euf-viper-build-features",
    }:
        raise ProvenanceError("sealed build artifact set differs")
    for name, record in sealed_artifacts.items():
        if type(record) is not dict:
            raise ProvenanceError(f"sealed build artifact {name} must be an object")
        require_exact_keys(record, {"bytes", "name", "sha256"}, f"sealed artifact {name}")
        if record["name"] != name or not HEX64.fullmatch(record["sha256"]):
            raise ProvenanceError(f"sealed build artifact {name} binding is invalid")
    receipt_bytes, _ = read_regular_nofollow(
        Path(sealed_build["receipt_path"]), "sealed build receipt"
    )
    if sha256_bytes(receipt_bytes) != sealed_build["receipt_sha256"]:
        raise ProvenanceError("sealed build receipt SHA-256 drifted")
    receipt_value = strict_json_load_bytes(
        receipt_bytes, Path(sealed_build["receipt_path"])
    )
    if canonical_bytes(receipt_value) != receipt_bytes:
        raise ProvenanceError("sealed build receipt is not canonical JSON")
    require_exact_keys(
        receipt_value,
        {
            "artifacts",
            "build",
            "independent_attestation",
            "schema",
            "sealed_build_manifest_sha256",
            "source",
            "status",
        },
        "sealed build receipt",
    )
    receipt_source = receipt_value["source"]
    require_exact_keys(
        receipt_source,
        {"dirty", "revision", "snapshot_manifest_sha256", "tree"},
        "sealed build receipt source",
    )
    receipt_build = receipt_value["build"]
    require_exact_keys(
        receipt_build,
        {"execution_closure_sha256", "features", "profile", "target", "toolchain"},
        "sealed build receipt build",
    )
    receipt_artifacts = receipt_value["artifacts"]
    if type(receipt_artifacts) is not dict or set(receipt_artifacts) != set(
        sealed_artifacts
    ):
        raise ProvenanceError("sealed build receipt artifact set differs")
    for name, record in receipt_artifacts.items():
        require_exact_keys(
            record,
            {"bytes", "mode", "sha256"},
            f"sealed build receipt artifact {name}",
        )
        sealed_record = sealed_artifacts[name]
        if (
            record["bytes"] != sealed_record["bytes"]
            or record["sha256"] != sealed_record["sha256"]
            or record["mode"] != "0500"
        ):
            raise ProvenanceError("sealed build receipt artifact binding mismatch")
    if (
        receipt_value.get("schema") != "euf-viper.sealed-build-receipt.v3"
        or receipt_value.get("status") != "accepted"
        or receipt_value.get("sealed_build_manifest_sha256")
        != sealed_build["sha256"]
        or receipt_source["revision"] != value["revision"]
        or receipt_source["tree"] != provenance["source_tree"]
        or receipt_source["dirty"] is not False
        or receipt_source["snapshot_manifest_sha256"]
        != sealed_build["source_snapshot_manifest_sha256"]
        or receipt_build["execution_closure_sha256"]
        != sealed_build["build_execution_closure_sha256"]
        or receipt_build["features"] != value["build_features"]
        or receipt_build["profile"] != "release"
        or type(receipt_build["target"]) is not str
        or "linux" not in receipt_build["target"]
        or receipt_build["toolchain"] != sealed_toolchain
    ):
        raise ProvenanceError("sealed build receipt binding mismatch")
    attestation_bytes, _ = read_regular_nofollow(
        Path(sealed_build["attestation_path"]), "sealed build attestation"
    )
    if sha256_bytes(attestation_bytes) != sealed_build["attestation_sha256"]:
        raise ProvenanceError("sealed build attestation SHA-256 drifted")
    attestation = strict_json_load_bytes(
        attestation_bytes, Path(sealed_build["attestation_path"])
    )
    if canonical_bytes(attestation) != attestation_bytes:
        raise ProvenanceError("sealed build attestation is not canonical JSON")
    require_exact_keys(
        attestation,
        {
            "artifacts",
            "attestor_sha256",
            "build_inputs",
            "build_manifest_sha256",
            "closure_sha256",
            "features",
            "schema",
            "source",
            "status",
            "toolchain",
            "traces",
        },
        "sealed build attestation",
    )
    if (
        attestation != receipt_value["independent_attestation"]
        or attestation["schema"] != "euf-viper.sealed-build-attestation.v1"
        or attestation["status"] != "accepted"
        or attestation["attestor_sha256"]
        != provenance["attestor_helper_sha256"]
        or attestation["artifacts"] != receipt_artifacts
        or attestation["features"] != receipt_build["features"]
        or attestation["toolchain"] != sealed_toolchain
        or attestation["closure_sha256"]
        != sealed_build["build_execution_closure_sha256"]
        or attestation["build_manifest_sha256"] != sealed_build["sha256"]
    ):
        raise ProvenanceError("independent sealed build attestation binding mismatch")
    for field in ("attestor_sha256", "build_manifest_sha256", "closure_sha256"):
        if not HEX64.fullmatch(attestation[field]):
            raise ProvenanceError(f"sealed build attestation {field} is malformed")
    attested_source = attestation["source"]
    require_exact_keys(
        attested_source,
        {"bundle_sha256", "file_count", "manifest_sha256", "revision", "tree"},
        "sealed build attestation source",
    )
    if (
        attested_source["revision"] != receipt_source["revision"]
        or attested_source["tree"] != receipt_source["tree"]
        or attested_source["manifest_sha256"]
        != receipt_source["snapshot_manifest_sha256"]
        or type(attested_source["file_count"]) is not int
        or attested_source["file_count"] < 1
        or not HEX64.fullmatch(attested_source["bundle_sha256"])
    ):
        raise ProvenanceError("sealed build attested source differs")
    attested_inputs = attestation["build_inputs"]
    require_exact_keys(
        attested_inputs,
        {
            "archive_sha256",
            "cargo_sha256",
            "file_count",
            "index_sha256",
            "object_count",
            "rustc_sha256",
        },
        "sealed build attestation inputs",
    )
    if (
        any(
            not HEX64.fullmatch(attested_inputs[field])
            for field in ("archive_sha256", "cargo_sha256", "index_sha256", "rustc_sha256")
        )
        or type(attested_inputs["file_count"]) is not int
        or attested_inputs["file_count"] < 1
        or type(attested_inputs["object_count"]) is not int
        or attested_inputs["object_count"] < 1
    ):
        raise ProvenanceError("sealed build attested inputs differ")
    attested_traces = attestation["traces"]
    require_exact_keys(
        attested_traces,
        {
            "canonical_sha256",
            "discovery_raw_sha256",
            "network",
            "production_raw_sha256",
            "randomness_events",
            "time_events",
        },
        "sealed build attestation traces",
    )
    if (
        any(
            not HEX64.fullmatch(attested_traces[field])
            for field in ("canonical_sha256", "discovery_raw_sha256", "production_raw_sha256")
        )
        or attested_traces["network"] != "denied-and-namespaced"
        or type(attested_traces["randomness_events"]) is not int
        or attested_traces["randomness_events"] < 0
        or type(attested_traces["time_events"]) is not int
        or attested_traces["time_events"] < 0
    ):
        raise ProvenanceError("sealed build attested channels differ")
    if (
        sealed_artifacts["euf-viper"]["sha256"] != value["viper"]["sha256"]
        or sealed_artifacts["euf-viper"]["bytes"] != value["viper"]["bytes"]
        or sealed_artifacts["euf-viper-build-features"]["sha256"]
        != value["feature_report"]["sha256"]
        or sealed_artifacts["euf-viper-build-features"]["bytes"]
        != value["feature_report"]["bytes"]
    ):
        raise ProvenanceError("sealed build artifacts differ from prepared executables")
    closure = value["execution_closure"]
    if type(closure) is not dict:
        raise ProvenanceError("execution closure binding must be an object")
    require_exact_keys(closure, {"path", "sha256"}, "execution closure")
    closure_bytes, _ = read_regular_nofollow(Path(closure["path"]), "execution closure")
    if sha256_bytes(closure_bytes) != closure["sha256"]:
        raise ProvenanceError("execution closure manifest SHA-256 drifted")
    closure_value = strict_json_load_bytes(closure_bytes, Path(closure["path"]))
    if canonical_bytes(closure_value) != closure_bytes:
        raise ProvenanceError("execution closure is not canonical JSON")
    require_exact_keys(
        closure_value,
        {
            "schema",
            "artifacts",
            "executables",
            "libraries",
            "python_runtime",
            "resolver",
            "virtual_libraries",
        },
        "execution closure",
    )
    if closure_value["schema"] != "euf-viper.linux-execution-closure.v3":
        raise ProvenanceError("execution closure schema mismatch")
    if set(closure_value["artifacts"]) != {
        "checker",
        "independent-parser",
        "libz3",
        "ld-cache",
        "sealed-build",
        "sealed-build-attestation",
        "sealed-build-receipt",
    } or set(closure_value["executables"]) != {
        "euf-viper",
        "feature-report",
        "git",
        "python",
        "unshare",
        "z3",
        "cvc5",
        "yices2",
        "opensmt",
    }:
        raise ProvenanceError("execution closure member set differs")
    for name, record in closure_value["artifacts"].items():
        if type(record) is not dict:
            raise ProvenanceError(f"execution closure artifact {name} must be an object")
        require_exact_keys(
            record,
            {"bytes", "category", "name", "path", "sha256"},
            f"execution closure artifact {name}",
        )
        if record["name"] != name or record["category"] != "bound_artifact":
            raise ProvenanceError(f"execution closure artifact {name} identity differs")
    for name, record in closure_value["executables"].items():
        if type(record) is not dict:
            raise ProvenanceError(f"execution closure executable {name} must be an object")
        require_exact_keys(
            record,
            {
                "bytes",
                "category",
                "name",
                "path",
                "sha256",
                "dynamic_dependencies",
                "ldd_sha256",
            },
            f"execution closure executable {name}",
        )
        if record["name"] != name or record["category"] != "executable":
            raise ProvenanceError(f"execution closure executable {name} identity differs")
    if type(closure_value["libraries"]) is not list or type(
        closure_value["virtual_libraries"]
    ) is not list:
        raise ProvenanceError("execution closure library records must be arrays")
    for index, record in enumerate(closure_value["libraries"]):
        if type(record) is not dict:
            raise ProvenanceError("execution closure library must be an object")
        require_exact_keys(
            record,
            {"bytes", "category", "path", "sha256"},
            f"execution closure library {index}",
        )
        if record["category"] != "dynamic_library":
            raise ProvenanceError("execution closure library category differs")
    resolver = closure_value["resolver"]
    require_exact_keys(
        resolver,
        {
            "interpreter",
            "interpreter_dynamic_dependencies",
            "interpreter_ldd_sha256",
            "program",
        },
        "execution closure resolver",
    )
    resolver_program = resolver["program"]
    require_exact_keys(
        resolver_program,
        {"bytes", "category", "name", "path", "sha256"},
        "execution closure resolver program",
    )
    if resolver_program["category"] != "loader_resolver":
        raise ProvenanceError("execution closure resolver identity differs")
    python_runtime = closure_value["python_runtime"]
    require_exact_keys(
        python_runtime,
        {"executable_name", "native_extensions", "probe", "probe_sha256"},
        "execution closure Python runtime",
    )
    if python_runtime["executable_name"] != "python":
        raise ProvenanceError("execution closure Python executable differs")
    probe = python_runtime["probe"]
    require_exact_keys(
        probe,
        {
            "builtin_or_frozen_modules",
            "files",
            "implementation",
            "modules",
            "runtime_roots",
            "scripts",
            "version",
        },
        "execution closure Python probe",
    )
    if sha256_bytes(canonical_bytes(probe)) != python_runtime["probe_sha256"]:
        raise ProvenanceError("execution closure Python probe hash differs")
    probe_paths = {
        record["path"] for record in probe["files"] if type(record) is dict
    }
    library_paths = {
        record["path"]
        for record in closure_value["libraries"]
        if type(record) is dict
    }
    native_paths: set[str] = set()
    if type(python_runtime["native_extensions"]) is not list:
        raise ProvenanceError("execution closure native extensions must be an array")
    for index, record in enumerate(python_runtime["native_extensions"]):
        require_exact_keys(
            record,
            {"dynamic_dependencies", "ldd_sha256", "path"},
            f"execution closure native extension {index}",
        )
        if (
            record["path"] not in probe_paths
            or record["path"] in native_paths
            or type(record["dynamic_dependencies"]) is not list
            or any(path not in library_paths for path in record["dynamic_dependencies"])
            or not HEX64.fullmatch(record["ldd_sha256"])
        ):
            raise ProvenanceError("execution closure native extension differs")
        native_paths.add(record["path"])
    closure_records = list(closure_value.get("artifacts", {}).values())
    closure_records.extend(closure_value.get("executables", {}).values())
    closure_records.extend(closure_value.get("libraries", []))
    closure_records.append(resolver_program)
    if resolver["interpreter"] is not None:
        closure_records.append(resolver["interpreter"])
    closure_records.extend(probe.get("scripts", {}).values())
    closure_records.extend(probe.get("files", []))
    for record in closure_records:
        if type(record) is not dict:
            raise ProvenanceError("execution closure member must be an object")
        data, metadata = read_regular_nofollow(Path(record["path"]), "execution closure member")
        if metadata.st_size != record["bytes"] or sha256_bytes(data) != record["sha256"]:
            raise ProvenanceError(f"execution closure member drifted: {record['path']}")
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
    if type(value["solver_executables"]) is not dict or set(
        value["solver_executables"]
    ) != {"euf-viper", "z3-default", "z3-sat-euf", "cvc5", "yices2", "opensmt"}:
        raise ProvenanceError("solver executable binding set differs")
    for name, record in value["solver_executables"].items():
        verify_bound_executable(record, f"solver {name}")
    executable_hashes = {
        name: record["sha256"] for name, record in closure_value["executables"].items()
    }
    if (
        executable_hashes["euf-viper"] != value["viper"]["sha256"]
        or executable_hashes["feature-report"] != value["feature_report"]["sha256"]
        or executable_hashes["python"] != value["runtime_tools"]["python"]["sha256"]
        or executable_hashes["z3"] != value["solver_executables"]["z3-default"]["sha256"]
        or executable_hashes["z3"] != value["solver_executables"]["z3-sat-euf"]["sha256"]
        or executable_hashes["cvc5"] != value["solver_executables"]["cvc5"]["sha256"]
        or executable_hashes["yices2"] != value["solver_executables"]["yices2"]["sha256"]
        or executable_hashes["opensmt"] != value["solver_executables"]["opensmt"]["sha256"]
        or closure_value["artifacts"]["sealed-build"]["sha256"]
        != sealed_build["sha256"]
        or closure_value["artifacts"]["sealed-build-receipt"]["sha256"]
        != sealed_build["receipt_sha256"]
        or closure_value["artifacts"]["sealed-build-attestation"]["sha256"]
        != sealed_build["attestation_sha256"]
    ):
        raise ProvenanceError("execution closure differs from prepared runtime bindings")
    libz3 = closure_value["artifacts"]["libz3"]
    if not any(
        record["path"] == libz3["path"] and record["sha256"] == libz3["sha256"]
        for record in closure_value["libraries"]
    ):
        raise ProvenanceError("execution closure does not dynamically bind the hashed libz3")
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
    prepare.add_argument("--expected-sha256", required=True)

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
