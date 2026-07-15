#!/usr/bin/env python3
"""Inventory Linux executables, loaders, shared libraries, and bound artifacts."""

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
from typing import Any


SCHEMA = "euf-viper.linux-execution-closure.v1"
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


def create_manifest(
    executables: dict[str, Path], artifacts: dict[str, Path], ldd: Path
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
    artifact_records = {
        name: record(path, "bound_artifact", name) for name, path in artifacts.items()
    }
    return {
        "schema": SCHEMA,
        "artifacts": artifact_records,
        "executables": executable_records,
        "libraries": [libraries[path] for path in sorted(libraries)],
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
        {"schema", "artifacts", "executables", "libraries", "virtual_libraries"},
        "execution closure",
    )
    if canonical_bytes(value) != raw or value["schema"] != SCHEMA:
        raise ClosureError("execution-closure manifest is not canonical or has wrong schema")
    artifacts = value["artifacts"]
    executables = value["executables"]
    libraries = value["libraries"]
    virtual = value["virtual_libraries"]
    if type(artifacts) is not dict or type(executables) is not dict:
        raise ClosureError("execution-closure bindings must be objects")
    if type(libraries) is not list or type(virtual) is not list:
        raise ClosureError("execution-closure library fields must be arrays")
    if len({item.get("path") for item in libraries if type(item) is dict}) != len(libraries):
        raise ClosureError("execution-closure libraries contain duplicate paths")
    library_paths = {item.get("path") for item in libraries if type(item) is dict}
    for name, item in artifacts.items():
        require_exact_keys(
            item,
            {"bytes", "category", "name", "path", "sha256"},
            f"artifact {name}",
        )
        if item["name"] != name or item["category"] != "bound_artifact":
            raise ClosureError(f"artifact {name} identity differs")
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
    for index, item in enumerate(libraries):
        require_exact_keys(
            item,
            {"bytes", "category", "path", "sha256"},
            f"library {index}",
        )
        if item["category"] != "dynamic_library":
            raise ClosureError("execution closure library category differs")
    records = list(artifacts.values())
    records.extend(executables.values())
    records.extend(libraries)
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
    create.add_argument("--ldd", type=Path, required=True)
    create.add_argument("--out", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--expected-sha256", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "create":
            value = create_manifest(
                binding(args.executable, "executable"),
                binding(args.artifact, "artifact"),
                args.ldd.resolve(strict=True),
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
