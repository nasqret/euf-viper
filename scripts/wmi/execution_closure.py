#!/usr/bin/env python3
"""Inventory and revalidate a closed Linux executable/Python runtime set."""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import re
import runpy
import stat
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path
from typing import Any


SCHEMA = "euf-viper.linux-execution-closure.v3"
NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
REQUIRED_SEALS = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE


class ClosureError(ValueError):
    """Raised when a Linux execution closure is incomplete or mutable."""


def is_hash(value: Any) -> bool:
    return type(value) is str and HEX64.fullmatch(value) is not None


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ClosureError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise ClosureError(f"{label} keys differ from the execution-closure schema")
    return value


def stable_read(path: Path, label: str) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ClosureError(f"{label} is not a regular file: {path}")
        chunks: list[bytes] = []
        size = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
            size += len(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if identity(before) != identity(after) or size != after.st_size:
        raise ClosureError(f"{label} changed while it was inventoried: {path}")
    return b"".join(chunks), after


def descriptor_bytes(descriptor: int, label: str) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        chunks.append(block)
    after = os.fstat(descriptor)
    raw = b"".join(chunks)
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if identity(before) != identity(after) or len(raw) != after.st_size:
        raise ClosureError(f"{label} changed while its exact descriptor was read")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return raw, after


def open_verified_descriptor(path: Path, label: str) -> tuple[int, str]:
    expected, expected_metadata = stable_read(path, label)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        actual, actual_metadata = descriptor_bytes(descriptor, label)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if actual != expected or identity(actual_metadata) != identity(expected_metadata):
            raise ClosureError(f"{label} descriptor differs from verified path bytes")
        return descriptor, hashlib.sha256(actual).hexdigest()
    except BaseException:
        os.close(descriptor)
        raise


def reverify_descriptor(descriptor: int, expected_sha256: str, label: str) -> None:
    raw, _ = descriptor_bytes(descriptor, label)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ClosureError(f"{label} changed while its descriptor was executed")


def current_helper_descriptor(label: str) -> tuple[int, str]:
    raw_path = str(__file__)
    prefix = "/proc/self/fd/"
    if raw_path.startswith(prefix) and raw_path[len(prefix) :].isdigit():
        descriptor = os.dup(int(raw_path[len(prefix) :]))
        try:
            raw, metadata = descriptor_bytes(descriptor, label)
            if not stat.S_ISREG(metadata.st_mode):
                raise ClosureError(f"{label} is not a regular file")
            return descriptor, hashlib.sha256(raw).hexdigest()
        except BaseException:
            os.close(descriptor)
            raise
    return open_verified_descriptor(Path(raw_path), label)


def mount(
    source: str | None,
    target: Path,
    filesystem: str | None,
    flags: int,
    data: str | None,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.mount(
        None if source is None else os.fsencode(source),
        os.fsencode(target),
        None if filesystem is None else os.fsencode(filesystem),
        ctypes.c_ulong(flags),
        None if data is None else os.fsencode(data),
    )
    if result != 0:
        error = ctypes.get_errno()
        raise ClosureError(f"mount failed for {target}: {os.strerror(error)}")


def binding(values: list[str], label: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        name, separator, raw_path = value.partition("=")
        if not separator or not NAME.fullmatch(name) or name in result:
            raise ClosureError(f"invalid or duplicate {label} binding {value!r}")
        path = Path(raw_path).resolve(strict=True)
        result[name] = path
    return dict(sorted(result.items()))


def record(path: Path, category: str, name: str | None = None) -> dict[str, Any]:
    content, metadata = stable_read(path, category)
    result: dict[str, Any] = {
        "bytes": metadata.st_size,
        "category": category,
        "path": str(path),
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    if name is not None:
        result["name"] = name
    return result


def execute_descriptor(
    executable: Path,
    arguments: list[str],
    *,
    pass_paths: tuple[Path, ...] = (),
) -> subprocess.CompletedProcess[bytes]:
    executable_fd, executable_sha256 = open_verified_descriptor(
        executable, "descriptor executable"
    )
    descriptors = [executable_fd]
    digests = [executable_sha256]
    try:
        for path in pass_paths:
            descriptor, digest = open_verified_descriptor(path, "descriptor input")
            descriptors.append(descriptor)
            digests.append(digest)
        command = [f"/proc/self/fd/{descriptors[0]}", *arguments]
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            pass_fds=tuple(descriptors),
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
        )
        for descriptor, digest in zip(descriptors, digests, strict=True):
            reverify_descriptor(descriptor, digest, "executed descriptor")
        return completed
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def ldd_output(ldd: Path, executable: Path) -> str:
    descriptor, ldd_sha256 = open_verified_descriptor(ldd, "loader resolver")
    executable_fd, executable_sha256 = open_verified_descriptor(
        executable, "loader target"
    )
    try:
        completed = subprocess.run(
            [f"/proc/self/fd/{descriptor}", f"/proc/self/fd/{executable_fd}"],
            capture_output=True,
            check=False,
            pass_fds=(descriptor, executable_fd),
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
        )
        reverify_descriptor(descriptor, ldd_sha256, "loader resolver")
        reverify_descriptor(executable_fd, executable_sha256, "loader target")
    finally:
        os.close(descriptor)
        os.close(executable_fd)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode("utf-8", "replace").strip()
        raise ClosureError(f"ldd rejected {executable}: {detail}")
    output = completed.stdout.decode("utf-8", "strict")
    if "not found" in output:
        raise ClosureError(f"dynamic dependency is missing for {executable}: {output.strip()}")
    return output


def resolver_interpreter(ldd: Path) -> Path | None:
    content, _ = stable_read(ldd, "loader resolver")
    first = content.splitlines()[0] if content else b""
    if not first.startswith(b"#!"):
        return None
    try:
        command = first[2:].decode("utf-8", "strict").strip().split()
    except UnicodeError as error:
        raise ClosureError("loader resolver has a non-UTF-8 shebang") from error
    if not command or not command[0].startswith("/"):
        raise ClosureError("loader resolver shebang is not an absolute executable")
    return Path(command[0]).resolve(strict=True)


def dependency_paths(output: str) -> tuple[list[Path], list[str]]:
    paths: set[Path] = set()
    virtual: set[str] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or "statically linked" in line:
            continue
        if line.startswith("linux-vdso"):
            virtual.add(line.split(" ", 1)[0])
            continue
        candidate = (
            line.split("=>", 1)[1].strip().split(" ", 1)[0]
            if "=>" in line
            else line.split(" ", 1)[0]
        )
        if candidate.startswith("/"):
            paths.add(Path(candidate).resolve(strict=True))
    return sorted(paths), sorted(virtual)


def loader_resolution_sha256(output: str) -> str:
    dependencies, virtual = dependency_paths(output)
    payload = {
        "dynamic_dependencies": [str(path) for path in dependencies],
        "virtual_libraries": virtual,
    }
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def python_probe_payload(scripts: dict[str, Path]) -> dict[str, Any]:
    for name, path in scripts.items():
        try:
            runpy.run_path(str(path), run_name=f"__euf_viper_probe_{name}__")
        except SystemExit as error:
            raise ClosureError(
                f"Python closure probe executed command code in {name}: {error}"
            ) from error

    files: dict[str, dict[str, Any]] = {}
    modules: list[dict[str, Any]] = []
    builtin_or_frozen: list[str] = []
    for name, module in sorted(sys.modules.items()):
        origins: set[str] = set()
        for raw in (
            getattr(module, "__file__", None),
            getattr(module, "__cached__", None),
            getattr(getattr(module, "__spec__", None), "origin", None),
        ):
            if raw in {"built-in", "frozen"}:
                builtin_or_frozen.append(name)
                continue
            if not isinstance(raw, str) or not raw:
                continue
            try:
                path = Path(raw).resolve(strict=True)
            except (FileNotFoundError, NotADirectoryError, RuntimeError):
                continue
            if not path.is_file():
                continue
            key = str(path)
            origins.add(key)
            if key not in files:
                files[key] = record(path, "python_runtime")
        modules.append({"name": name, "origins": sorted(origins)})
    script_records = {
        name: record(path.resolve(strict=True), "python_script", name)
        for name, path in scripts.items()
    }
    runtime_roots: set[Path] = set()
    for key in ("stdlib", "platstdlib"):
        raw = sysconfig.get_paths().get(key)
        if not raw:
            continue
        try:
            root = Path(raw).resolve(strict=True)
        except (FileNotFoundError, RuntimeError):
            continue
        if root.is_dir():
            runtime_roots.add(root)
    for root in sorted(runtime_roots):
        for candidate in sorted(root.rglob("*")):
            try:
                resolved = candidate.resolve(strict=True)
            except (FileNotFoundError, NotADirectoryError, RuntimeError):
                continue
            if not resolved.is_file():
                continue
            key = str(resolved)
            if key not in files:
                files[key] = record(resolved, "python_runtime")
    return {
        "builtin_or_frozen_modules": sorted(set(builtin_or_frozen)),
        "files": [files[path] for path in sorted(files)],
        "implementation": sys.implementation.name,
        "modules": modules,
        "runtime_roots": [str(path) for path in sorted(runtime_roots)],
        "scripts": script_records,
        "version": sys.version,
    }


def run_python_probe(python: Path, scripts: dict[str, Path]) -> dict[str, Any]:
    python_fd, python_sha256 = open_verified_descriptor(python, "Python probe executable")
    helper_fd, helper_sha256 = current_helper_descriptor("Python probe helper")
    descriptors = [python_fd, helper_fd]
    descriptor_hashes = [python_sha256, helper_sha256]
    try:
        script_arguments: list[str] = []
        for name, path in scripts.items():
            descriptor, digest = open_verified_descriptor(
                path, f"Python probe script {name}"
            )
            descriptors.append(descriptor)
            descriptor_hashes.append(digest)
            script_arguments.extend(
                ["--script", f"{name}=/proc/self/fd/{descriptor}"]
            )
        completed = subprocess.run(
            [
                f"/proc/self/fd/{descriptors[0]}",
                "-B",
                "-I",
                "-S",
                f"/proc/self/fd/{descriptors[1]}",
                "_python_probe",
                *script_arguments,
            ],
            capture_output=True,
            check=False,
            pass_fds=tuple(descriptors),
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
        )
        for descriptor, digest in zip(descriptors, descriptor_hashes, strict=True):
            reverify_descriptor(descriptor, digest, "Python probe input")
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(
            "utf-8", "replace"
        ).strip()
        raise ClosureError(f"Python runtime closure probe failed: {detail}")
    try:
        value = json.loads(completed.stdout, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ClosureError(f"Python runtime probe returned invalid JSON: {error}") from error
    if canonical_bytes(value) != completed.stdout:
        raise ClosureError("Python runtime probe output is not canonical JSON")
    return value


def create_manifest(
    executables: dict[str, Path],
    artifacts: dict[str, Path],
    ldd: Path,
    *,
    python_executable_name: str,
    python_scripts: dict[str, Path],
) -> dict[str, Any]:
    if not sys.platform.startswith("linux") or not Path("/proc/self/fd").is_dir():
        raise ClosureError("execution-closure inventory requires Linux /proc/self/fd")
    executable_records: dict[str, dict[str, Any]] = {}
    libraries: dict[str, dict[str, Any]] = {}
    virtual: set[str] = set()
    for name, path in executables.items():
        if not os.access(path, os.X_OK):
            raise ClosureError(f"bound executable is not executable: {path}")
        output = ldd_output(ldd, path)
        dependencies, names = dependency_paths(output)
        virtual.update(names)
        executable_records[name] = {
            **record(path, "executable", name),
            "dynamic_dependencies": [str(item) for item in dependencies],
            "ldd_sha256": loader_resolution_sha256(output),
        }
        for dependency in dependencies:
            libraries[str(dependency)] = record(dependency, "dynamic_library")
    if python_executable_name not in executables:
        raise ClosureError(
            "Python runtime closure names an executable absent from --executable"
        )
    if not python_scripts:
        raise ClosureError("Python runtime closure requires at least one bound script")
    resolver_program = record(ldd, "loader_resolver", "ldd")
    interpreter = resolver_interpreter(ldd)
    interpreter_record: dict[str, Any] | None = None
    interpreter_dependencies: list[str] = []
    interpreter_ldd_sha256: str | None = None
    if interpreter is not None:
        output = ldd_output(ldd, interpreter)
        dependencies, names = dependency_paths(output)
        virtual.update(names)
        interpreter_record = record(
            interpreter, "loader_resolver_interpreter", "interpreter"
        )
        interpreter_dependencies = [str(path) for path in dependencies]
        interpreter_ldd_sha256 = loader_resolution_sha256(output)
        for dependency in dependencies:
            libraries[str(dependency)] = record(dependency, "dynamic_library")
    artifact_records = {
        name: record(path, "bound_artifact", name) for name, path in artifacts.items()
    }
    python_runtime = run_python_probe(
        executables[python_executable_name], python_scripts
    )
    native_extensions: list[dict[str, Any]] = []
    for item in python_runtime["files"]:
        path = Path(item["path"])
        content, _ = stable_read(path, "Python native extension probe")
        if not content.startswith(b"\x7fELF"):
            continue
        output = ldd_output(ldd, path)
        dependencies, names = dependency_paths(output)
        virtual.update(names)
        native_extensions.append(
            {
                "dynamic_dependencies": [str(dependency) for dependency in dependencies],
                "ldd_sha256": loader_resolution_sha256(output),
                "path": str(path),
            }
        )
        for dependency in dependencies:
            libraries[str(dependency)] = record(dependency, "dynamic_library")
    return {
        "schema": SCHEMA,
        "artifacts": artifact_records,
        "executables": executable_records,
        "libraries": [libraries[path] for path in sorted(libraries)],
        "python_runtime": {
            "executable_name": python_executable_name,
            "native_extensions": native_extensions,
            "probe": python_runtime,
            "probe_sha256": hashlib.sha256(
                canonical_bytes(python_runtime)
            ).hexdigest(),
        },
        "resolver": {
            "interpreter": interpreter_record,
            "interpreter_dynamic_dependencies": interpreter_dependencies,
            "interpreter_ldd_sha256": interpreter_ldd_sha256,
            "program": resolver_program,
        },
        "virtual_libraries": sorted(virtual),
    }


def verify_manifest(path: Path, expected_sha256: str) -> dict[str, Any]:
    if not is_hash(expected_sha256):
        raise ClosureError("expected execution-closure SHA-256 is malformed")
    raw, _ = stable_read(path, "execution-closure manifest")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ClosureError("execution-closure manifest SHA-256 mismatch")
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ClosureError(f"invalid execution-closure manifest: {error}") from error
    require_exact_keys(
        value,
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
    if canonical_bytes(value) != raw or value["schema"] != SCHEMA:
        raise ClosureError("execution-closure manifest is not canonical or has wrong schema")
    artifacts = value["artifacts"]
    executables = value["executables"]
    libraries = value["libraries"]
    python_runtime = require_exact_keys(
        value["python_runtime"],
        {"executable_name", "native_extensions", "probe", "probe_sha256"},
        "Python runtime closure",
    )
    resolver = require_exact_keys(
        value["resolver"],
        {
            "interpreter",
            "interpreter_dynamic_dependencies",
            "interpreter_ldd_sha256",
            "program",
        },
        "loader resolver",
    )
    virtual = value["virtual_libraries"]
    if type(artifacts) is not dict or type(executables) is not dict:
        raise ClosureError("execution-closure bindings must be objects")
    if type(libraries) is not list or type(virtual) is not list:
        raise ClosureError("execution-closure library fields must be arrays")
    if len({item.get("path") for item in libraries if type(item) is dict}) != len(libraries):
        raise ClosureError("execution-closure libraries contain duplicate paths")
    library_paths = {item.get("path") for item in libraries if type(item) is dict}

    def require_current(item: dict[str, Any], label: str) -> None:
        current = record(Path(item["path"]), item["category"], item.get("name"))
        current.pop("name", None)
        expected = {
            key: item[key]
            for key in ("bytes", "category", "path", "sha256")
        }
        if current != expected:
            raise ClosureError(f"execution closure drifted at {item['path']} ({label})")

    for index, item in enumerate(libraries):
        require_exact_keys(
            item,
            {"bytes", "category", "path", "sha256"},
            f"library {index}",
        )
        if item["category"] != "dynamic_library":
            raise ClosureError("execution closure library category differs")
        require_current(item, f"library {index}")
    resolver_program = require_exact_keys(
        resolver["program"],
        {"bytes", "category", "name", "path", "sha256"},
        "loader resolver program",
    )
    if (
        resolver_program["category"] != "loader_resolver"
        or resolver_program["name"] != "ldd"
    ):
        raise ClosureError("loader resolver identity differs")
    require_current(resolver_program, "loader resolver")
    resolver_interpreter_record = resolver["interpreter"]
    if resolver_interpreter_record is None:
        if (
            resolver["interpreter_dynamic_dependencies"] != []
            or resolver["interpreter_ldd_sha256"] is not None
        ):
            raise ClosureError("binary loader resolver has script-interpreter fields")
    else:
        require_exact_keys(
            resolver_interpreter_record,
            {"bytes", "category", "name", "path", "sha256"},
            "loader resolver interpreter",
        )
        if (
            resolver_interpreter_record["category"]
            != "loader_resolver_interpreter"
            or resolver_interpreter_record["name"] != "interpreter"
            or type(resolver["interpreter_dynamic_dependencies"]) is not list
            or any(
                path not in library_paths
                for path in resolver["interpreter_dynamic_dependencies"]
            )
            or not is_hash(resolver["interpreter_ldd_sha256"])
        ):
            raise ClosureError("loader resolver interpreter closure differs")
        require_current(resolver_interpreter_record, "loader resolver interpreter")
    for name, item in artifacts.items():
        require_exact_keys(
            item,
            {"bytes", "category", "name", "path", "sha256"},
            f"artifact {name}",
        )
        if item["name"] != name or item["category"] != "bound_artifact":
            raise ClosureError(f"artifact {name} identity differs")
        require_current(item, f"artifact {name}")
    for name, item in executables.items():
        require_exact_keys(
            item,
            {
                "bytes",
                "category",
                "name",
                "path",
                "sha256",
                "dynamic_dependencies",
                "ldd_sha256",
            },
            f"executable {name}",
        )
        if (
            item["name"] != name
            or item["category"] != "executable"
            or type(item["dynamic_dependencies"]) is not list
            or not is_hash(item["ldd_sha256"])
            or any(path not in library_paths for path in item["dynamic_dependencies"])
        ):
            raise ClosureError(f"executable {name} closure differs")
        if not os.access(item["path"], os.X_OK):
            raise ClosureError(f"execution closure executable is no longer executable: {name}")
        require_current(item, f"executable {name}")
        output = ldd_output(Path(resolver_program["path"]), Path(item["path"]))
        dependencies, resolved_virtual = dependency_paths(output)
        if (
            [str(path) for path in dependencies] != item["dynamic_dependencies"]
            or loader_resolution_sha256(output) != item["ldd_sha256"]
            or any(name not in virtual for name in resolved_virtual)
        ):
            raise ClosureError(f"dynamic loader resolution drifted for executable {name}")
    if resolver_interpreter_record is not None:
        output = ldd_output(
            Path(resolver_program["path"]),
            Path(resolver_interpreter_record["path"]),
        )
        dependencies, resolved_virtual = dependency_paths(output)
        if (
            [str(path) for path in dependencies]
            != resolver["interpreter_dynamic_dependencies"]
            or loader_resolution_sha256(output) != resolver["interpreter_ldd_sha256"]
            or any(name not in virtual for name in resolved_virtual)
        ):
            raise ClosureError("dynamic loader resolution drifted for resolver interpreter")

    if (
        type(python_runtime["executable_name"]) is not str
        or python_runtime["executable_name"] not in executables
        or not is_hash(python_runtime["probe_sha256"])
        or hashlib.sha256(canonical_bytes(python_runtime["probe"])).hexdigest()
        != python_runtime["probe_sha256"]
    ):
        raise ClosureError("Python runtime probe binding is malformed")
    probe = require_exact_keys(
        python_runtime["probe"],
        {
            "builtin_or_frozen_modules",
            "files",
            "implementation",
            "modules",
            "runtime_roots",
            "scripts",
            "version",
        },
        "Python runtime probe",
    )
    if (
        type(probe["files"]) is not list
        or type(probe["modules"]) is not list
        or type(probe["runtime_roots"]) is not list
        or any(type(path) is not str or not path.startswith("/") for path in probe["runtime_roots"])
        or type(probe["scripts"]) is not dict
        or not probe["scripts"]
        or type(probe["builtin_or_frozen_modules"]) is not list
    ):
        raise ClosureError("Python runtime probe fields are malformed")
    python_scripts: dict[str, Path] = {}
    for name, item in probe["scripts"].items():
        require_exact_keys(
            item,
            {"bytes", "category", "name", "path", "sha256"},
            f"Python script {name}",
        )
        if item["name"] != name or item["category"] != "python_script":
            raise ClosureError(f"Python script {name} identity differs")
        require_current(item, f"Python script {name}")
        python_scripts[name] = Path(item["path"])
    for index, item in enumerate(probe["files"]):
        require_exact_keys(
            item,
            {"bytes", "category", "path", "sha256"},
            f"Python runtime file {index}",
        )
        if item["category"] != "python_runtime":
            raise ClosureError("Python runtime file category differs")
        require_current(item, f"Python runtime file {index}")
    rerun_probe = run_python_probe(
        Path(executables[python_runtime["executable_name"]]["path"]),
        python_scripts,
    )
    if rerun_probe != probe:
        raise ClosureError("Python imported-module closure drifted")
    probe_file_paths = {item["path"] for item in probe["files"]}
    native_extension_paths: set[str] = set()
    if type(python_runtime["native_extensions"]) is not list:
        raise ClosureError("Python native-extension closure must be an array")
    for index, item in enumerate(python_runtime["native_extensions"]):
        require_exact_keys(
            item,
            {"dynamic_dependencies", "ldd_sha256", "path"},
            f"Python native extension {index}",
        )
        if (
            item["path"] not in probe_file_paths
            or item["path"] in native_extension_paths
            or type(item["dynamic_dependencies"]) is not list
            or any(path not in library_paths for path in item["dynamic_dependencies"])
            or not is_hash(item["ldd_sha256"])
        ):
            raise ClosureError("Python native-extension closure differs")
        native_extension_paths.add(item["path"])
        content, _ = stable_read(Path(item["path"]), "Python native extension")
        if not content.startswith(b"\x7fELF"):
            raise ClosureError("Python native-extension binding is not ELF")
        output = ldd_output(Path(resolver_program["path"]), Path(item["path"]))
        dependencies, resolved_virtual = dependency_paths(output)
        if (
            [str(path) for path in dependencies] != item["dynamic_dependencies"]
            or loader_resolution_sha256(output) != item["ldd_sha256"]
            or any(name not in virtual for name in resolved_virtual)
        ):
            raise ClosureError("Python native-extension loader resolution drifted")
    records = list(artifacts.values())
    records.extend(executables.values())
    records.extend(libraries)
    records.append(resolver_program)
    if resolver_interpreter_record is not None:
        records.append(resolver_interpreter_record)
    records.extend(probe["scripts"].values())
    records.extend(probe["files"])
    for item in records:
        if type(item["bytes"]) is not int or item["bytes"] < 0 or not is_hash(
            item["sha256"]
        ):
            raise ClosureError("execution closure contains malformed size or digest")
        current = record(Path(item["path"]), item["category"], item.get("name"))
        current.pop("name", None)
        expected = {
            key: item[key]
            for key in ("bytes", "category", "path", "sha256")
        }
        if current != expected:
            raise ClosureError(f"execution closure drifted at {item['path']}")
    return {
        "manifest": str(path.resolve(strict=True)),
        "manifest_sha256": expected_sha256,
        "status": "accepted",
    }


def freeze_file(path: Path, expected_sha256: str, label: str) -> int:
    if not hasattr(os, "memfd_create") or not hasattr(os, "MFD_ALLOW_SEALING"):
        raise ClosureError(f"{label} requires Linux sealed memfd support")
    content, metadata = stable_read(path, label)
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ClosureError(f"{label} SHA-256 differs before sealing")
    descriptor = os.memfd_create(
        f"euf-viper-runtime-{path.name}",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise ClosureError(f"{label} had a short memfd write")
            offset += written
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode))
        os.fsync(descriptor)
        fcntl.fcntl(descriptor, F_ADD_SEALS, REQUIRED_SEALS)
        if fcntl.fcntl(descriptor, F_GET_SEALS) & REQUIRED_SEALS != REQUIRED_SEALS:
            raise ClosureError(f"{label} memfd lacks required seals")
        os.lseek(descriptor, 0, os.SEEK_SET)
        frozen = bytearray()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            frozen.extend(block)
        if hashlib.sha256(frozen).hexdigest() != expected_sha256:
            raise ClosureError(f"{label} sealed bytes differ")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def freeze_content(content: bytes, mode: int, expected_sha256: str, label: str) -> int:
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ClosureError(f"{label} bytes differ before sealing")
    descriptor = os.memfd_create(
        f"euf-viper-runtime-{label}", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    )
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise ClosureError(f"{label} had a short memfd write")
            offset += written
        os.fchmod(descriptor, stat.S_IMODE(mode))
        os.fsync(descriptor)
        fcntl.fcntl(descriptor, F_ADD_SEALS, REQUIRED_SEALS)
        if fcntl.fcntl(descriptor, F_GET_SEALS) & REQUIRED_SEALS != REQUIRED_SEALS:
            raise ClosureError(f"{label} memfd lacks required seals")
        frozen, _ = descriptor_bytes(descriptor, label)
        if hashlib.sha256(frozen).hexdigest() != expected_sha256:
            raise ClosureError(f"{label} sealed bytes differ")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def closure_records(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}

    def add(item: dict[str, Any]) -> None:
        path = item["path"]
        previous = records.get(path)
        identity = {
            key: item[key] for key in ("bytes", "path", "sha256")
        }
        if previous is not None:
            prior_identity = {
                key: previous[key] for key in ("bytes", "path", "sha256")
            }
            if identity != prior_identity:
                raise ClosureError(f"execution closure has conflicting records for {path}")
            return
        records[path] = item

    for item in value["artifacts"].values():
        add(item)
    for item in value["executables"].values():
        add(item)
    for item in value["libraries"]:
        add(item)
    resolver = value["resolver"]
    add(resolver["program"])
    if resolver["interpreter"] is not None:
        add(resolver["interpreter"])
    probe = value["python_runtime"]["probe"]
    for item in probe["scripts"].values():
        add(item)
    for item in probe["files"]:
        add(item)
    return dict(sorted(records.items()))


def _root_path(root: Path, absolute: Path) -> Path:
    if not absolute.is_absolute() or ".." in absolute.parts:
        raise ClosureError(f"runtime path is not a safe absolute path: {absolute}")
    return root.joinpath(*absolute.parts[1:])


def _write_root_file(
    root: Path,
    source: Path,
    *,
    expected_sha256: str | None,
    expected_bytes: int | None,
    executable: bool,
    label: str,
) -> None:
    content, metadata = stable_read(source, label)
    if expected_sha256 is not None and hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ClosureError(f"{label} SHA-256 drifted during root materialization")
    if expected_bytes is not None and len(content) != expected_bytes:
        raise ClosureError(f"{label} byte count drifted during root materialization")
    destination = _root_path(root, source)
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    mode = 0o555 if executable else 0o444
    if destination.exists():
        existing, _ = stable_read(destination, f"materialized {label}")
        if existing != content:
            raise ClosureError(f"runtime root collision at {source}")
        if executable:
            destination.chmod(0o555)
        return
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
    )
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise ClosureError(f"short runtime-root write for {source}")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if metadata.st_size != len(content):
        raise ClosureError(f"{label} changed while copied")


def _copy_declared_root(source: Path, root: Path) -> None:
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ClosureError(f"declared runtime data root is not a directory: {source}")
    destination_root = _root_path(root, source)
    destination_root.mkdir(mode=0o755, parents=True, exist_ok=True)
    for current, directory_names, file_names in os.walk(source, followlinks=False):
        current_path = Path(current)
        target_directory = _root_path(root, current_path)
        target_directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        for name in sorted(tuple(directory_names)):
            candidate = current_path / name
            metadata = candidate.lstat()
            if not stat.S_ISLNK(metadata.st_mode):
                continue
            resolved = candidate.resolve(strict=True)
            try:
                resolved.relative_to(source)
            except ValueError as error:
                raise ClosureError(
                    f"runtime data symlink escapes declared root: {candidate}"
                ) from error
            link = _root_path(root, candidate)
            if not os.path.lexists(link):
                link.symlink_to(os.readlink(candidate))
            directory_names.remove(name)
        for name in sorted(file_names):
            candidate = current_path / name
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                resolved = candidate.resolve(strict=True)
                try:
                    resolved.relative_to(source)
                except ValueError as error:
                    raise ClosureError(
                        f"runtime data symlink escapes declared root: {candidate}"
                    ) from error
                link = _root_path(root, candidate)
                if not os.path.lexists(link):
                    link.symlink_to(os.readlink(candidate))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ClosureError(f"runtime data root contains a special file: {candidate}")
            _write_root_file(
                root,
                candidate,
                expected_sha256=None,
                expected_bytes=None,
                executable=bool(metadata.st_mode & 0o111),
                label=f"runtime data {candidate}",
            )


def _manifest_from_descriptor(descriptor: int, expected_sha256: str) -> dict[str, Any]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        chunks.append(block)
    raw = b"".join(chunks)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ClosureError("sealed execution-closure descriptor SHA-256 differs")
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ClosureError(f"sealed execution closure is invalid: {error}") from error
    if canonical_bytes(value) != raw or value.get("schema") != SCHEMA:
        raise ClosureError("sealed execution closure is noncanonical or has wrong schema")
    return value


def launch_inside(args: argparse.Namespace) -> int:
    if not sys.platform.startswith("linux"):
        raise ClosureError("descriptor-bound runtime launch requires Linux")
    value = _manifest_from_descriptor(args.manifest_fd, args.expected_sha256)
    command = json.loads(args.launch_command)
    environment = json.loads(args.environment)
    if (
        type(command) is not list
        or not command
        or any(type(item) is not str or not item for item in command)
        or type(environment) is not dict
        or any(type(key) is not str or type(setting) is not str for key, setting in environment.items())
    ):
        raise ClosureError("runtime launch command or environment is malformed")
    for name in ("LD_PRELOAD", "LD_AUDIT", "PYTHONHOME", "PYTHONPATH"):
        if name in environment:
            raise ClosureError(f"runtime launch forbids ambient {name}")
    records = closure_records(value)
    copy_roots = json.loads(args.copy_roots)
    if copy_roots != []:
        raise ClosureError("unbound recursive runtime copy roots are forbidden")
    command_path = str(Path(command[0]).resolve(strict=True))
    executable_paths = {
        item["path"] for item in value["executables"].values()
    }
    if command_path not in executable_paths:
        raise ClosureError("runtime command is absent from the executable closure")

    root = Path(args.root)
    root.mkdir(mode=0o700)
    mount(None, Path("/"), None, MS_REC | MS_PRIVATE, None)
    mount("tmpfs", root, "tmpfs", MS_NOSUID | MS_NODEV, "mode=0700")
    executable_set = set(executable_paths)
    for raw_path, item in records.items():
        _write_root_file(
            root,
            Path(raw_path),
            expected_sha256=item["sha256"],
            expected_bytes=item["bytes"],
            executable=raw_path in executable_set,
            label=f"closed runtime file {raw_path}",
        )
    for standard in (Path("/bin"), Path("/lib"), Path("/lib64"), Path("/sbin")):
        if not standard.is_symlink():
            continue
        destination = _root_path(root, standard)
        if not os.path.lexists(destination):
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            destination.symlink_to(os.readlink(standard))

    for directory in (Path("/proc"), Path("/dev"), Path(args.cwd)):
        _root_path(root, directory).mkdir(mode=0o755, parents=True, exist_ok=True)
    ephemeral_roots = {
        Path(environment[name])
        for name in ("HOME", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME")
        if name in environment
    }
    for ephemeral in ephemeral_roots:
        if not ephemeral.is_absolute() or ".." in ephemeral.parts:
            raise ClosureError(f"runtime ephemeral root is unsafe: {ephemeral}")
        _root_path(root, ephemeral).mkdir(mode=0o700, parents=True, exist_ok=True)
    writable_roots = [Path(path).resolve(strict=True) for path in json.loads(args.writable_roots)]
    read_only_roots = [Path(path).resolve(strict=True) for path in json.loads(args.read_only_roots)]
    for read_only in read_only_roots:
        if not read_only.is_dir():
            raise ClosureError(f"runtime read-only root is not a directory: {read_only}")
        _root_path(root, read_only).mkdir(mode=0o755, parents=True, exist_ok=True)
    for writable in writable_roots:
        _root_path(root, writable).mkdir(mode=0o700, parents=True, exist_ok=True)
    for device in (Path("/dev/null"), Path("/dev/zero"), Path("/dev/random"), Path("/dev/urandom")):
        target = _root_path(root, device)
        target.touch(mode=0o600, exist_ok=True)

    mount(None, root, None, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, None)
    for read_only in read_only_roots:
        target = _root_path(root, read_only)
        mount(str(read_only), target, None, MS_BIND | MS_REC, None)
        mount(
            None,
            target,
            None,
            MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
            None,
        )
    for writable in writable_roots:
        target = _root_path(root, writable)
        mount(str(writable), target, None, MS_BIND | MS_REC, None)
    for ephemeral in sorted(ephemeral_roots):
        mount(
            "tmpfs",
            _root_path(root, ephemeral),
            "tmpfs",
            MS_NOSUID | MS_NODEV,
            "mode=0700,size=64m",
        )
    mount("proc", _root_path(root, Path("/proc")), "proc", MS_NOSUID | MS_NODEV, None)
    for device in (Path("/dev/null"), Path("/dev/zero"), Path("/dev/random"), Path("/dev/urandom")):
        mount(str(device), _root_path(root, device), None, MS_BIND, None)

    command[0] = command_path
    os.chroot(root)
    os.chdir(args.cwd)
    os.execve(command[0], command, environment)
    raise AssertionError("execve unexpectedly returned")


def launch(args: argparse.Namespace) -> int:
    if not sys.platform.startswith("linux") or not Path("/proc/self/fd").is_dir():
        raise ClosureError("descriptor-bound runtime launch requires Linux /proc/self/fd")
    argv = args.argv[1:] if args.argv and args.argv[0] == "--" else args.argv
    if not argv:
        raise ClosureError("runtime launch requires a command after --")
    if args.copy_root:
        raise ClosureError("unbound recursive runtime copy roots are forbidden")
    verify_manifest(args.manifest, args.expected_sha256)
    raw, _ = stable_read(args.manifest, "execution-closure manifest")
    value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    python_record = value["executables"].get(args.python_executable_name)
    unshare_record = value["executables"].get(args.unshare_executable_name)
    if python_record is None or unshare_record is None:
        raise ClosureError("runtime launch requires closed Python and unshare executables")
    descriptors = [
        freeze_file(args.manifest, args.expected_sha256, "execution-closure manifest"),
        freeze_file(
            Path(python_record["path"]), python_record["sha256"], "runtime Python"
        ),
        freeze_file(
            Path(unshare_record["path"]), unshare_record["sha256"], "runtime unshare"
        ),
    ]
    helper_source, helper_sha256 = current_helper_descriptor("runtime closure helper")
    try:
        helper_content, helper_metadata = descriptor_bytes(
            helper_source, "runtime closure helper"
        )
    finally:
        os.close(helper_source)
    descriptors.append(
        freeze_content(
            helper_content,
            helper_metadata.st_mode,
            helper_sha256,
            "runtime-closure-helper",
        )
    )
    staging = args.staging_root.resolve(strict=True)
    if not staging.is_dir():
        raise ClosureError("runtime closure staging root must already exist")
    root = Path(tempfile.mkdtemp(prefix="closed-runtime-", dir=staging))
    try:
        command = [str(Path(argv[0]).resolve(strict=True)), *argv[1:]]
        completed = subprocess.run(
            [
                f"/proc/self/fd/{descriptors[2]}",
                "--user",
                "--map-root-user",
                "--mount",
                "--net",
                "--pid",
                "--fork",
                "--",
                f"/proc/self/fd/{descriptors[1]}",
                "-B",
                "-I",
                "-S",
                f"/proc/self/fd/{descriptors[3]}",
                "_launch_inside",
                "--manifest-fd",
                str(descriptors[0]),
                "--expected-sha256",
                args.expected_sha256,
                "--root",
                str(root),
                "--cwd",
                str(args.cwd.resolve(strict=True)),
                "--copy-roots",
                json.dumps([str(path.resolve(strict=True)) for path in args.copy_root]),
                "--writable-roots",
                json.dumps([str(path.resolve(strict=True)) for path in args.writable_root]),
                "--read-only-roots",
                json.dumps([str(path.resolve(strict=True)) for path in args.read_only_root]),
                "--environment",
                json.dumps(dict(os.environ), sort_keys=True, separators=(",", ":")),
                "--command",
                json.dumps(command, separators=(",", ":")),
            ],
            check=False,
            pass_fds=tuple(descriptors),
            stdin=subprocess.DEVNULL,
        )
        return completed.returncode
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        try:
            root.rmdir()
        except FileNotFoundError:
            pass


def atomic_create(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--executable", action="append", default=[])
    create.add_argument("--artifact", action="append", default=[])
    create.add_argument("--python-executable-name", required=True)
    create.add_argument("--python-script", action="append", default=[])
    create.add_argument("--ldd", type=Path, required=True)
    create.add_argument("--out", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--expected-sha256", required=True)
    launch_parser = subparsers.add_parser("launch")
    launch_parser.add_argument("--manifest", type=Path, required=True)
    launch_parser.add_argument("--expected-sha256", required=True)
    launch_parser.add_argument("--staging-root", type=Path, required=True)
    launch_parser.add_argument("--cwd", type=Path, required=True)
    launch_parser.add_argument("--copy-root", type=Path, action="append", default=[])
    launch_parser.add_argument("--writable-root", type=Path, action="append", default=[])
    launch_parser.add_argument("--read-only-root", type=Path, action="append", default=[])
    launch_parser.add_argument("--python-executable-name", default="python")
    launch_parser.add_argument("--unshare-executable-name", default="unshare")
    launch_parser.add_argument("argv", nargs=argparse.REMAINDER)
    launch_inside_parser = subparsers.add_parser("_launch_inside")
    launch_inside_parser.add_argument("--manifest-fd", type=int, required=True)
    launch_inside_parser.add_argument("--expected-sha256", required=True)
    launch_inside_parser.add_argument("--root", required=True)
    launch_inside_parser.add_argument("--cwd", required=True)
    launch_inside_parser.add_argument("--copy-roots", required=True)
    launch_inside_parser.add_argument("--writable-roots", required=True)
    launch_inside_parser.add_argument("--read-only-roots", required=True)
    launch_inside_parser.add_argument("--environment", required=True)
    launch_inside_parser.add_argument("--command", dest="launch_command", required=True)
    python_probe = subparsers.add_parser("_python_probe")
    python_probe.add_argument("--script", action="append", default=[])
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "_python_probe":
            scripts = binding(args.script, "Python script")
            if not scripts:
                raise ClosureError("Python runtime closure requires bound scripts")
            print(canonical_bytes(python_probe_payload(scripts)).decode(), end="")
            return 0
        if args.command == "_launch_inside":
            return launch_inside(args)
        if args.command == "launch":
            if not args.argv:
                raise ClosureError("runtime launch requires a command after --")
            return launch(args)
        if args.command == "create":
            value = create_manifest(
                binding(args.executable, "executable"),
                binding(args.artifact, "artifact"),
                args.ldd.resolve(strict=True),
                python_executable_name=args.python_executable_name,
                python_scripts=binding(args.python_script, "Python script"),
            )
            raw = canonical_bytes(value)
            atomic_create(args.out, raw)
            result = {
                "manifest": str(args.out.resolve(strict=True)),
                "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                "status": "created",
            }
        else:
            result = verify_manifest(args.manifest, args.expected_sha256)
    except (OSError, ClosureError, KeyError, TypeError) as error:
        print(f"execution closure rejected: {error}", file=sys.stderr)
        return 2
    print(canonical_bytes(result).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
