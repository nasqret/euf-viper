#!/usr/bin/env python3
"""Inventory and revalidate a closed Linux executable/Python runtime set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import runpy
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA = "euf-viper.linux-execution-closure.v2"
NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


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
    descriptors = [os.open(executable, os.O_RDONLY | os.O_NOFOLLOW)]
    try:
        descriptors.extend(
            os.open(path, os.O_RDONLY | os.O_NOFOLLOW) for path in pass_paths
        )
        command = [f"/proc/self/fd/{descriptors[0]}", *arguments]
        return subprocess.run(
            command,
            capture_output=True,
            check=False,
            pass_fds=tuple(descriptors),
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def ldd_output(ldd: Path, executable: Path) -> str:
    descriptor = os.open(ldd, os.O_RDONLY | os.O_NOFOLLOW)
    executable_fd = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        completed = subprocess.run(
            [f"/proc/self/fd/{descriptor}", f"/proc/self/fd/{executable_fd}"],
            capture_output=True,
            check=False,
            pass_fds=(descriptor, executable_fd),
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
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
    return {
        "builtin_or_frozen_modules": sorted(set(builtin_or_frozen)),
        "files": [files[path] for path in sorted(files)],
        "implementation": sys.implementation.name,
        "modules": modules,
        "scripts": script_records,
        "version": sys.version,
    }


def run_python_probe(python: Path, scripts: dict[str, Path]) -> dict[str, Any]:
    helper = Path(__file__).resolve(strict=True)
    descriptors = [
        os.open(python, os.O_RDONLY | os.O_NOFOLLOW),
        os.open(helper, os.O_RDONLY | os.O_NOFOLLOW),
    ]
    try:
        script_arguments: list[str] = []
        for name, path in scripts.items():
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            descriptors.append(descriptor)
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
        )
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
            "ldd_sha256": hashlib.sha256(output.encode()).hexdigest(),
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
        interpreter_ldd_sha256 = hashlib.sha256(output.encode()).hexdigest()
        for dependency in dependencies:
            libraries[str(dependency)] = record(dependency, "dynamic_library")
    artifact_records = {
        name: record(path, "bound_artifact", name) for name, path in artifacts.items()
    }
    python_runtime = run_python_probe(
        executables[python_executable_name], python_scripts
    )
    return {
        "schema": SCHEMA,
        "artifacts": artifact_records,
        "executables": executable_records,
        "libraries": [libraries[path] for path in sorted(libraries)],
        "python_runtime": {
            "executable_name": python_executable_name,
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
        {"executable_name", "probe", "probe_sha256"},
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
            or hashlib.sha256(output.encode()).hexdigest() != item["ldd_sha256"]
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
            or hashlib.sha256(output.encode()).hexdigest()
            != resolver["interpreter_ldd_sha256"]
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
            "scripts",
            "version",
        },
        "Python runtime probe",
    )
    if (
        type(probe["files"]) is not list
        or type(probe["modules"]) is not list
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
