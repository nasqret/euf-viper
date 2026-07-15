#!/usr/bin/env python3
"""Build production evidence from a sealed Linux source/toolchain snapshot."""

from __future__ import annotations

import argparse
import ast
import ctypes
import errno
import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA = "euf-viper.sealed-linux-build.v3"
SOURCE_SCHEMA = "euf-viper.sealed-source-snapshot.v1"
CLOSURE_SCHEMA = "euf-viper.build-execution-closure.v3"
RECEIPT_SCHEMA = "euf-viper.sealed-build-receipt.v3"
TRACE_SCHEMA = "euf-viper.canonical-build-trace.v1"
TRACE_SET_SCHEMA = "euf-viper.canonical-build-traces.v1"
INPUTS_SCHEMA = "euf-viper.retained-build-inputs.v1"
ATTESTATION_SCHEMA = "euf-viper.sealed-build-attestation.v1"
HEX_REVISION = frozenset("0123456789abcdef")
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
RENAME_NOREPLACE = 1
PR_SET_DUMPABLE = 4
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
REQUIRED_SEALS = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE


class SealedBuildError(ValueError):
    """Raised when Linux cannot enforce the production build boundary."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_linux() -> None:
    if not sys.platform.startswith("linux"):
        raise SealedBuildError(
            "production evidence requires Linux user/mount namespaces, sealed memfd, "
            "and read-only bind mounts"
        )
    if not Path("/proc/self/fd").is_dir():
        raise SealedBuildError("production evidence requires a mounted /proc/self/fd")
    if not hasattr(os, "memfd_create") or not hasattr(os, "MFD_ALLOW_SEALING"):
        raise SealedBuildError("production evidence requires memfd_create with sealing")


def stable_read(path: Path, label: str) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SealedBuildError(f"cannot open {label} {path} without links: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SealedBuildError(f"{label} is not a regular file: {path}")
        blocks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            blocks.append(block)
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
    content = b"".join(blocks)
    if identity(before) != identity(after) or len(content) != after.st_size:
        raise SealedBuildError(f"{label} changed while it was read: {path}")
    return content, after


def checked_executable(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    content, metadata = stable_read(resolved, label)
    del content
    if not os.access(resolved, os.X_OK) or not stat.S_ISREG(metadata.st_mode):
        raise SealedBuildError(f"{label} is not executable: {resolved}")
    return resolved


def stable_command(
    executable: Path,
    arguments: Iterable[str],
    *,
    environment: dict[str, str],
    cwd: Path | None = None,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    descriptor = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        expected_sha256 = sha256_bytes(
            read_open_descriptor(descriptor, f"command executable {executable}")
        )
        command = [f"/proc/self/fd/{descriptor}", *arguments]
        options: dict[str, Any] = {
            "cwd": cwd,
            "env": environment,
            "capture_output": True,
            "check": False,
            "pass_fds": (descriptor,),
        }
        if input_bytes is None:
            options["stdin"] = subprocess.DEVNULL
        else:
            options["input"] = input_bytes
        completed = subprocess.run(
            command,
            **options,
        )
        reverify_open_descriptor(
            descriptor, expected_sha256, f"command executable {executable}"
        )
        return completed
    finally:
        os.close(descriptor)


def require_success(completed: subprocess.CompletedProcess[bytes], label: str) -> bytes:
    if completed.returncode != 0:
        raise SealedBuildError(
            f"{label} failed with {completed.returncode}: "
            f"{(completed.stderr or completed.stdout).decode('utf-8', 'replace').strip()}"
        )
    return completed.stdout


def file_record(path: str, content: bytes, mode: int, category: str) -> dict[str, Any]:
    return {
        "bytes": len(content),
        "category": category,
        "mode": f"{stat.S_IMODE(mode):04o}",
        "path": path,
        "sha256": sha256_bytes(content),
    }


def fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def require_private_directory(path: Path, label: str) -> Path:
    absolute = path.absolute()
    resolved = path.resolve(strict=True)
    if absolute != resolved:
        raise SealedBuildError(f"{label} path contains a symlink: {path}")
    metadata = resolved.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise SealedBuildError(f"{label} must be a directory owned by the build UID")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SealedBuildError(f"{label} must deny group and other access: {resolved}")
    return resolved


def git_snapshot(
    repository: Path, revision: str, git: Path, environment: dict[str, str]
) -> list[tuple[str, bytes, int, str]]:
    if len(revision) not in {40, 64} or any(char not in HEX_REVISION for char in revision):
        raise SealedBuildError("revision must be a full lowercase Git object id")
    archive = require_success(
        stable_command(
            git,
            ["-C", str(repository), "archive", "--format=tar", revision],
            environment=environment,
        ),
        "git archive",
    )
    records: list[tuple[str, bytes, int, str]] = []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
        for member in source.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise SealedBuildError(f"Git archive contains unsafe path {member.name!r}")
            if member.isdir():
                continue
            if not member.isfile():
                raise SealedBuildError(
                    f"Git snapshot contains unsupported non-file {member.name!r}"
                )
            handle = source.extractfile(member)
            if handle is None:
                raise SealedBuildError(f"cannot read Git archive member {member.name!r}")
            records.append((path.as_posix(), handle.read(), member.mode, "git"))
    if not records:
        raise SealedBuildError("Git snapshot is empty")
    return sorted(records)


def vendor_snapshot(root: Path) -> list[tuple[str, bytes, int, str]]:
    records: list[tuple[str, bytes, int, str]] = []
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise SealedBuildError(f"Cargo vendor snapshot contains non-file {path}")
        relative = path.relative_to(root).as_posix()
        content, stable = stable_read(path, "Cargo vendor input")
        records.append(
            (
                f"vendor-registry/{relative}",
                content,
                stat.S_IMODE(stable.st_mode),
                "cargo_registry",
            )
        )
    if not records:
        raise SealedBuildError("cargo vendor produced an empty registry snapshot")
    return records


def add_tar_file(archive: tarfile.TarFile, name: str, content: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = stat.S_IMODE(mode)
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    archive.addfile(info, io.BytesIO(content))


def sealed_bundle(
    records: list[tuple[str, bytes, int, str]],
    revision: str,
    tree: str,
) -> tuple[int, dict[str, Any], str]:
    source_manifest = {
        "schema": SOURCE_SCHEMA,
        "revision": revision,
        "tree": tree,
        "files": [file_record(path, content, mode, category) for path, content, mode, category in records],
    }
    manifest_bytes = canonical_bytes(source_manifest)
    manifest_sha256 = sha256_bytes(manifest_bytes)
    descriptor = os.memfd_create(
        "euf-viper-source-snapshot",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        with os.fdopen(os.dup(descriptor), "wb", closefd=True) as raw:
            with tarfile.open(fileobj=raw, mode="w|") as archive:
                for path, content, mode, _ in records:
                    add_tar_file(archive, path, content, mode)
                add_tar_file(
                    archive,
                    ".euf-viper-sealed-source-manifest.json",
                    manifest_bytes,
                    0o444,
                )
            raw.flush()
            os.fsync(raw.fileno())
        fcntl.fcntl(descriptor, F_ADD_SEALS, REQUIRED_SEALS)
        if fcntl.fcntl(descriptor, F_GET_SEALS) & REQUIRED_SEALS != REQUIRED_SEALS:
            raise SealedBuildError("source snapshot memfd did not retain every required seal")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, source_manifest, manifest_sha256
    except BaseException:
        os.close(descriptor)
        raise


def read_sealed_descriptor(descriptor: int, label: str) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        chunks.append(block)
    content = b"".join(chunks)
    if not content:
        raise SealedBuildError(f"{label} is empty")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return content


def sealed_content_descriptor(name: str, content: bytes, mode: int) -> int:
    if not content:
        raise SealedBuildError(f"cannot seal empty {name}")
    descriptor = os.memfd_create(
        f"euf-viper-{name}", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    )
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise SealedBuildError(f"short sealed write for {name}")
            offset += written
        os.fchmod(descriptor, stat.S_IMODE(mode))
        os.fsync(descriptor)
        fcntl.fcntl(descriptor, F_ADD_SEALS, REQUIRED_SEALS)
        if fcntl.fcntl(descriptor, F_GET_SEALS) & REQUIRED_SEALS != REQUIRED_SEALS:
            raise SealedBuildError(f"sealed {name} descriptor lacks required seals")
        if read_sealed_descriptor(descriptor, name) != content:
            raise SealedBuildError(f"sealed {name} descriptor bytes differ")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_verified_descriptor(path: Path, label: str) -> tuple[int, str]:
    expected, expected_metadata = stable_read(path, label)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SealedBuildError(f"{label} descriptor is not a regular file")
        content = read_open_descriptor(descriptor, label)
        digest = sha256_bytes(content)
        if (
            content != expected
            or fingerprint(metadata) != fingerprint(expected_metadata)
            or not metadata.st_mode & 0o111
        ):
            raise SealedBuildError(f"{label} descriptor differs from verified bytes")
        return descriptor, digest
    except BaseException:
        os.close(descriptor)
        raise


def read_open_descriptor(descriptor: int, label: str) -> bytes:
    before = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        chunks.append(block)
    after = os.fstat(descriptor)
    content = b"".join(chunks)
    if fingerprint(before) != fingerprint(after) or len(content) != after.st_size:
        raise SealedBuildError(f"{label} changed while its exact descriptor was read")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return content


def reverify_open_descriptor(descriptor: int, expected_sha256: str, label: str) -> None:
    if sha256_bytes(read_open_descriptor(descriptor, label)) != expected_sha256:
        raise SealedBuildError(f"{label} changed while it was executed")


def current_helper_bytes() -> tuple[bytes, os.stat_result]:
    raw_path = str(__file__)
    prefix = "/proc/self/fd/"
    if raw_path.startswith(prefix) and raw_path[len(prefix) :].isdigit():
        descriptor = os.dup(int(raw_path[len(prefix) :]))
        try:
            content = read_open_descriptor(descriptor, "current sealed build helper")
            metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        return content, metadata
    return stable_read(Path(raw_path), "current sealed build helper")


def retained_input_bundle(
    paths: dict[Path, str],
) -> tuple[bytes, dict[str, Any]]:
    records: list[dict[str, Any]] = []
    objects: dict[str, tuple[bytes, int]] = {}
    for path, category in sorted(paths.items(), key=lambda item: str(item[0])):
        resolved = path.resolve(strict=True)
        content, metadata = stable_read(resolved, f"retained {category} input")
        digest = sha256_bytes(content)
        objects.setdefault(digest, (content, stat.S_IMODE(metadata.st_mode)))
        records.append(
            {
                "bytes": len(content),
                "category": category,
                "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                "object": f"objects/{digest}",
                "path": str(resolved),
                "sha256": digest,
            }
        )
    index = {
        "files": records,
        "object_count": len(objects),
        "schema": INPUTS_SCHEMA,
    }
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:") as archive:
        for digest, (content, mode) in sorted(objects.items()):
            add_tar_file(archive, f"objects/{digest}", content, mode)
        add_tar_file(
            archive,
            "retained-build-inputs.json",
            canonical_bytes(index),
            0o400,
        )
    return raw.getvalue(), index


def mount(source: str | None, target: Path, filesystem: str | None, flags: int, data: str | None) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = None if source is None else os.fsencode(source)
    filesystem_bytes = None if filesystem is None else os.fsencode(filesystem)
    data_bytes = None if data is None else os.fsencode(data)
    result = libc.mount(
        source_bytes,
        os.fsencode(target),
        filesystem_bytes,
        ctypes.c_ulong(flags),
        data_bytes,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise SealedBuildError(
            f"mount enforcement failed for {target}: {os.strerror(error)}; "
            "enable unprivileged user namespaces and mount capability inside them"
        )


def set_nondumpable() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise SealedBuildError(f"cannot disable same-UID process inspection: {os.strerror(error)}")


def safe_extract(descriptor: int, destination: Path) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    with os.fdopen(os.dup(descriptor), "rb") as raw:
        with tarfile.open(fileobj=raw, mode="r:") as archive:
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or not member.isfile():
                    raise SealedBuildError(f"sealed bundle contains unsafe member {member.name!r}")
                output = destination.joinpath(*path.parts)
                output.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise SealedBuildError(f"cannot extract sealed member {member.name!r}")
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                fd = os.open(output, flags, member.mode & 0o777)
                try:
                    content = source.read()
                    offset = 0
                    while offset < len(content):
                        offset += os.write(fd, content[offset:])
                    os.fchmod(fd, member.mode & 0o777)
                    os.fsync(fd)
                finally:
                    os.close(fd)


def verify_source_snapshot(
    source: Path,
    manifest: dict[str, Any],
    *,
    revision: str,
    tree: str,
) -> None:
    if (
        manifest.get("schema") != SOURCE_SCHEMA
        or manifest.get("revision") != revision
        or manifest.get("tree") != tree
        or type(manifest.get("files")) is not list
    ):
        raise SealedBuildError("sealed source manifest identity is invalid")
    expected: dict[str, dict[str, Any]] = {}
    for item in manifest["files"]:
        if type(item) is not dict or set(item) != {
            "bytes",
            "category",
            "mode",
            "path",
            "sha256",
        }:
            raise SealedBuildError("sealed source manifest contains a malformed file record")
        relative = PurePosixPath(item["path"])
        if relative.is_absolute() or ".." in relative.parts or item["path"] in expected:
            raise SealedBuildError("sealed source manifest contains an unsafe or duplicate path")
        expected[item["path"]] = item
    actual_paths: set[str] = set()
    for path in sorted(source.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise SealedBuildError(f"sealed source contains a non-file entry: {path}")
        relative = path.relative_to(source).as_posix()
        if relative == ".euf-viper-sealed-source-manifest.json":
            continue
        actual_paths.add(relative)
        item = expected.get(relative)
        if item is None:
            raise SealedBuildError(f"sealed source contains an unbound file: {relative}")
        content, stable = stable_read(path, "sealed source")
        if (
            item["bytes"] != stable.st_size
            or item["mode"] != f"{stat.S_IMODE(stable.st_mode):04o}"
            or item["sha256"] != sha256_bytes(content)
        ):
            raise SealedBuildError(f"sealed source file differs from its manifest: {relative}")
    if actual_paths != set(expected):
        raise SealedBuildError("sealed source manifest lists missing files")


def materialize_git_snapshot(
    records: list[tuple[str, bytes, int, str]], destination: Path
) -> None:
    destination.mkdir(mode=0o700)
    for relative, content, mode, category in records:
        if category != "git":
            continue
        path = destination.joinpath(*PurePosixPath(relative).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            stat.S_IMODE(mode),
        )
        try:
            offset = 0
            while offset < len(content):
                offset += os.write(descriptor, content[offset:])
            os.fchmod(descriptor, stat.S_IMODE(mode))
        finally:
            os.close(descriptor)


def validate_internal_symlinks(root: Path) -> None:
    resolved_root = root.resolve(strict=True)
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if not stat.S_ISLNK(metadata.st_mode):
            continue
        target = os.readlink(path)
        if os.path.isabs(target):
            raise SealedBuildError(f"copied Rust toolchain has an absolute symlink: {path}")
        try:
            path.resolve(strict=True).relative_to(resolved_root)
        except (OSError, ValueError) as error:
            raise SealedBuildError(
                f"copied Rust toolchain symlink escapes its read-only snapshot: {path}"
            ) from error


def inventory_tree(root: Path, category: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(root).as_posix()
        if stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(path)
            records.append(
                {
                    "category": category,
                    "kind": "symlink",
                    "path": relative,
                    "target": target,
                }
            )
        elif stat.S_ISREG(metadata.st_mode):
            content, stable = stable_read(path, category)
            records.append(
                {
                    **file_record(relative, content, stable.st_mode, category),
                    "kind": "file",
                }
            )
        elif not stat.S_ISDIR(metadata.st_mode):
            raise SealedBuildError(f"unsupported {category} entry {path}")
    return records


def inventory_identity(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {key: value for key, value in record.items() if key != "category"}
        for record in records
    ]


def copy_tree_verified(source: Path, destination: Path, category: str) -> list[dict[str, Any]]:
    before = inventory_tree(source, category)
    shutil.copytree(source, destination, symlinks=True)
    validate_internal_symlinks(destination)
    after = inventory_tree(source, category)
    copied = inventory_tree(destination, category)
    if inventory_identity(before) != inventory_identity(after):
        raise SealedBuildError(f"{category} changed while it was copied")
    if inventory_identity(before) != inventory_identity(copied):
        raise SealedBuildError(f"copied {category} differs byte-for-byte from its source")
    return copied


def ldd_paths(ldd: Path, executable: Path, environment: dict[str, str]) -> list[Path]:
    output = require_success(
        stable_command(ldd, [str(executable)], environment=environment),
        f"dynamic closure for {executable}",
    ).decode("utf-8", "strict")
    if "not found" in output:
        raise SealedBuildError(f"dynamic closure is incomplete for {executable}: {output.strip()}")
    paths: set[Path] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or "statically linked" in line or line.startswith("linux-vdso"):
            continue
        candidate = line.split("=>", 1)[1].strip().split(" ", 1)[0] if "=>" in line else line.split(" ", 1)[0]
        if candidate.startswith("/"):
            paths.add(Path(candidate).resolve(strict=True))
    return sorted(paths)


def require_unreplaceable_external_path(path: Path) -> None:
    if os.access(path, os.W_OK):
        raise SealedBuildError(
            f"native build tool or library is writable by the build UID: {path}"
        )
    parent = path.parent
    while True:
        if os.access(parent, os.W_OK):
            raise SealedBuildError(
                f"native build tool or library parent is replaceable by the build UID: {parent}"
            )
        if parent == parent.parent:
            break
        parent = parent.parent


def native_closure(
    tools: dict[str, tuple[Path, bool]],
    ldd: Path,
    environment: dict[str, str],
    *,
    copied_roots: tuple[Path, ...] = (),
) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    queue: list[tuple[str, Path, bool]] = [
        (category, binding[0], binding[1])
        for category, binding in sorted(tools.items())
    ]
    while queue:
        category, path, copied_read_only = queue.pop(0)
        resolved = path.resolve(strict=True)
        key = str(resolved)
        if key in records:
            continue
        if not copied_read_only:
            require_unreplaceable_external_path(resolved)
        content, metadata = stable_read(resolved, category)
        records[key] = {
            "bytes": metadata.st_size,
            "category": category,
            "path": key,
            "sha256": sha256_bytes(content),
        }
        for dependency in ldd_paths(ldd, resolved, environment):
            copied_dependency = False
            for root in copied_roots:
                try:
                    dependency.relative_to(root)
                except ValueError:
                    continue
                copied_dependency = True
                break
            queue.append(("dynamic_library", dependency, copied_dependency))
    return [records[key] for key in sorted(records)]


TRACE_ANNOTATION = re.compile(r"<(/(?:\\.|[^>])*)>")
TRACE_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')
TRACE_LEADING_PID = re.compile(r"^(?:\[pid +)?([0-9]+)(?:\] +| +)")
FORBIDDEN_NETWORK = re.compile(
    r"\b(?:connect|accept|accept4|sendto|recvfrom|sendmsg|recvmsg)\("
    r"|\bsocket\((?:AF_INET|AF_INET6|AF_NETLINK|AF_PACKET)"
)


def _trace_string(raw: str) -> str:
    try:
        value = ast.literal_eval(raw)
    except (SyntaxError, ValueError) as error:
        raise SealedBuildError(f"cannot decode strace pathname {raw!r}") from error
    if type(value) is not str:
        raise SealedBuildError("strace pathname did not decode to text")
    return value.removesuffix(" (deleted)")


def normalize_virtual_path(raw: str) -> str:
    value = re.sub(r"^/proc/[0-9]+", "/proc/$PID", raw)
    value = re.sub(r"^/proc/(?:self|\$PID)/fd/[0-9]+", "/proc/self/fd/$FD", value)
    value = re.sub(r"^/dev/fd/[0-9]+", "/dev/fd/$FD", value)
    return value


def canonical_trace_payload(
    raw: bytes, *, workspace: Path, phase: str
) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise SealedBuildError(f"{phase} strace output is not UTF-8") from error
    pid_names: dict[str, str] = {}
    lines: list[str] = []
    network_lines: list[str] = []
    randomness_lines: list[str] = []
    time_lines: list[str] = []
    for raw_line in text.splitlines():
        if "strace: Process" in raw_line:
            continue
        line = raw_line
        match = TRACE_LEADING_PID.match(line)
        if match is not None:
            pid = match.group(1)
            name = pid_names.setdefault(pid, f"$PID{len(pid_names)}")
            line = name + " " + line[match.end() :]
        line = line.replace(str(workspace), "$WORKSPACE")
        line = re.sub(r"/proc/[0-9]+", "/proc/$PID", line)
        if FORBIDDEN_NETWORK.search(line):
            network_lines.append(line)
        if "getrandom(" in line or "/dev/urandom" in line or "/dev/random" in line:
            randomness_lines.append(line)
        if re.search(r"\b(?:clock_gettime|clock_getres|gettimeofday|time)\(", line):
            time_lines.append(line)
        lines.append(line)
    if not lines:
        raise SealedBuildError(f"{phase} strace output has no syscall records")
    if network_lines:
        raise SealedBuildError(
            f"{phase} build attempted a denied network channel: {network_lines[0]}"
        )
    canonical_lines = ("\n".join(lines) + "\n").encode("utf-8")
    return {
        "canonical_lines": lines,
        "canonical_sha256": sha256_bytes(canonical_lines),
        "channels": {
            "network": "denied",
            "randomness_events": len(randomness_lines),
            "time_events": len(time_lines),
        },
        "phase": phase,
        "raw_sha256": sha256_bytes(raw),
        "schema": TRACE_SCHEMA,
    }


def traced_paths(trace: Path) -> tuple[set[Path], set[Path], set[str], set[str]]:
    content, _ = stable_read(trace, "build access trace")
    try:
        text = content.decode("utf-8", "strict")
    except UnicodeError as error:
        raise SealedBuildError("build access trace is not UTF-8") from error
    paths: set[Path] = set()
    directories: set[Path] = set()
    virtual: set[str] = set()
    missing: set[str] = set()
    for line in text.splitlines():
        failed = " = -1 " in line
        candidates: set[str] = set()
        for match in TRACE_ANNOTATION.finditer(line):
            candidates.add(match.group(1).removesuffix(" (deleted)"))
        for match in TRACE_QUOTED.finditer(line):
            value = _trace_string(match.group(0))
            candidates.add(value)
        for raw in candidates:
            if failed:
                missing.add(
                    normalize_virtual_path(raw)
                    if raw.startswith(("/proc/", "/sys/", "/dev/"))
                    else raw
                )
                continue
            if not raw.startswith("/"):
                continue
            if raw.startswith(("/proc/", "/sys/", "/dev/")):
                virtual.add(normalize_virtual_path(raw))
                continue
            path = Path(raw)
            try:
                metadata = path.stat()
            except (FileNotFoundError, NotADirectoryError):
                continue
            if stat.S_ISREG(metadata.st_mode):
                paths.add(path.resolve(strict=True))
            elif stat.S_ISDIR(metadata.st_mode):
                directories.add(path.resolve(strict=True))
    return paths, directories, virtual, missing


def directory_record(path: Path) -> dict[str, Any]:
    require_unreplaceable_external_path(path)
    before = path.stat()
    entries: list[dict[str, str]] = []
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in sorted(os.listdir(descriptor)):
            metadata = os.stat(
                name, dir_fd=descriptor, follow_symlinks=False
            )
            kind = (
                "file"
                if stat.S_ISREG(metadata.st_mode)
                else "directory"
                if stat.S_ISDIR(metadata.st_mode)
                else "symlink"
                if stat.S_ISLNK(metadata.st_mode)
                else "other"
            )
            item = {"kind": kind, "name": name}
            if kind == "symlink":
                item["target"] = os.readlink(name, dir_fd=descriptor)
            entries.append(item)
    finally:
        os.close(descriptor)
    after = path.stat()
    if fingerprint(before) != fingerprint(after):
        raise SealedBuildError(f"external build directory changed during inventory: {path}")
    return {
        "entries_sha256": sha256_bytes(canonical_bytes(entries)),
        "path": str(path),
    }


def path_below(path: Path, roots: Iterable[Path]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
        except ValueError:
            continue
        return True
    return False


def trace_build(
    strace: Path,
    cargo: Path,
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    trace: Path,
    label: str,
) -> None:
    strace_fd = os.open(strace, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    cargo_fd = os.open(cargo, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        strace_sha256 = sha256_bytes(
            read_open_descriptor(strace_fd, "strace executable")
        )
        cargo_sha256 = sha256_bytes(
            read_open_descriptor(cargo_fd, "Cargo executable")
        )
        completed = subprocess.run(
            [
            f"/proc/self/fd/{strace_fd}",
            "-f",
            "-qq",
            "-yy",
            "-xx",
            "-v",
            "-s",
            "65535",
            "-o",
            str(trace),
            "-e",
            "trace=all",
            "--",
            f"/proc/self/fd/{cargo_fd}",
            *arguments,
            ],
            cwd=cwd,
            env=environment,
            capture_output=True,
            check=False,
            pass_fds=(strace_fd, cargo_fd),
            stdin=subprocess.DEVNULL,
        )
        reverify_open_descriptor(strace_fd, strace_sha256, "strace executable")
        reverify_open_descriptor(cargo_fd, cargo_sha256, "Cargo executable")
    finally:
        os.close(strace_fd)
        os.close(cargo_fd)
    require_success(completed, label)
    if not trace.is_file() or trace.stat().st_size == 0:
        raise SealedBuildError(f"{label} did not produce a file-access trace")


def python_runtime_snapshot(ldd: Path, environment: dict[str, str]) -> dict[str, Any]:
    helper_content, _ = current_helper_bytes()
    paths: set[Path] = {Path(sys.executable).resolve(strict=True)}
    frozen: set[str] = set()
    for name, module in sorted(sys.modules.items()):
        origin = getattr(module, "__file__", None)
        cached = getattr(module, "__cached__", None)
        found = False
        for raw in (origin, cached):
            if not isinstance(raw, str) or not raw:
                continue
            try:
                path = Path(raw).resolve(strict=True)
            except (FileNotFoundError, RuntimeError):
                continue
            if path.is_file():
                paths.add(path)
                found = True
        if not found:
            spec = getattr(module, "__spec__", None)
            module_origin = getattr(spec, "origin", None)
            if module_origin in {"built-in", "frozen"}:
                frozen.add(name)
    for dependency in ldd_paths(ldd, Path(sys.executable).resolve(strict=True), environment):
        paths.add(dependency)
    try:
        maps = Path("/proc/self/maps").read_bytes()
    except OSError as error:
        raise SealedBuildError(f"cannot inspect Python process memory map: {error}") from error
    for raw_line in maps.decode("utf-8", "strict").splitlines():
        fields = raw_line.split(maxsplit=5)
        if len(fields) != 6 or not fields[5].startswith("/"):
            continue
        raw_path = fields[5].removesuffix(" (deleted)")
        try:
            mapped = Path(raw_path).resolve(strict=True)
        except (FileNotFoundError, NotADirectoryError, RuntimeError):
            continue
        if mapped.is_file():
            paths.add(mapped)
    return {
        "files": [
            {
                "bytes": metadata.st_size,
                "path": str(path),
                "sha256": sha256_bytes(content),
            }
            for path in sorted(paths)
            for content, metadata in [stable_read(path, "Python runtime input")]
        ],
        "frozen_or_builtin_modules": sorted(frozen),
        "invoked_helper_sha256": sha256_bytes(helper_content),
        "implementation": sys.implementation.name,
        "version": sys.version,
    }


def seal_and_mount_file(path: Path) -> tuple[int, dict[str, Any]]:
    content, metadata = stable_read(path, "discovered build input")
    descriptor = os.memfd_create(
        f"euf-viper-build-input-{path.name}",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode))
        os.fsync(descriptor)
        fcntl.fcntl(descriptor, F_ADD_SEALS, REQUIRED_SEALS)
        if fcntl.fcntl(descriptor, F_GET_SEALS) & REQUIRED_SEALS != REQUIRED_SEALS:
            raise SealedBuildError(f"build input memfd was not sealed: {path}")
        mount(f"/proc/self/fd/{descriptor}", path, None, MS_BIND, None)
        mount(
            None,
            path,
            None,
            MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
            None,
        )
        mounted, mounted_metadata = stable_read(path, "mounted build input")
        if mounted != content or stat.S_IMODE(mounted_metadata.st_mode) != stat.S_IMODE(
            metadata.st_mode
        ):
            raise SealedBuildError(f"sealed build input mount differs: {path}")
        return descriptor, {
            "bytes": metadata.st_size,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "path": str(path),
            "sha256": sha256_bytes(content),
        }
    except BaseException:
        os.close(descriptor)
        raise


def compiler_subtools(
    compiler: Path, prefix: str, environment: dict[str, str]
) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for program in ("as", "ld", "collect2", "cc1", "cc1plus"):
        completed = stable_command(
            compiler,
            [f"-print-prog-name={program}"],
            environment=environment,
        )
        if completed.returncode != 0:
            continue
        raw = completed.stdout.decode("utf-8", "strict").strip()
        if not raw or raw == program:
            resolved = shutil.which(raw, path=environment["PATH"])
            if resolved is None:
                continue
            path = Path(resolved).resolve(strict=True)
        else:
            path = Path(raw).resolve(strict=True)
        result[f"{prefix}_{program}"] = path
    if not any(name.endswith("_ld") for name in result):
        raise SealedBuildError(f"cannot resolve linker used by native compiler {compiler}")
    return result


def verify_read_only(path: Path) -> None:
    probe = path / ".write-probe"
    try:
        descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        if error.errno in {errno.EROFS, errno.EACCES, errno.EPERM}:
            return
        raise SealedBuildError(f"read-only snapshot probe failed unexpectedly: {error}") from error
    else:
        os.close(descriptor)
        probe.unlink(missing_ok=True)
        raise SealedBuildError("source snapshot remained writable after read-only remount")


def same_identity(parent_fd: int, name: str, metadata: os.stat_result) -> bool:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return stat.S_ISREG(current.st_mode) and fingerprint(current) == fingerprint(metadata)


def publish_bytes(parent_fd: int, name: str, content: bytes, mode: int) -> dict[str, Any]:
    temporary = f".{name}.tmp-{os.getpid()}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
        dir_fd=parent_fd,
    )
    published = False
    complete = False
    metadata: os.stat_result | None = None
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise SealedBuildError(f"short publication write for {name}")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        os.link(
            temporary,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        published = True
        linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (linked.st_dev, linked.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise SealedBuildError(f"published path does not name checked inode: {name}")
        if not same_identity(parent_fd, temporary, os.fstat(descriptor)):
            raise SealedBuildError(f"staging path changed before cleanup: {name}")
        os.unlink(temporary, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
        if not same_identity(parent_fd, name, metadata):
            raise SealedBuildError(f"published path metadata differs: {name}")
        os.fsync(parent_fd)
        if not same_identity(parent_fd, name, metadata):
            raise SealedBuildError(f"published path changed during directory sync: {name}")
        complete = True
        return {"bytes": len(content), "name": name, "sha256": sha256_bytes(content)}
    finally:
        try:
            if metadata is not None:
                current = os.fstat(descriptor)
                if same_identity(parent_fd, temporary, current):
                    os.unlink(temporary, dir_fd=parent_fd)
                current = os.fstat(descriptor)
                if published and not complete and same_identity(parent_fd, name, current):
                    os.unlink(name, dir_fd=parent_fd)
        finally:
            os.close(descriptor)


def publish_build_set(
    parent_fd: int, payloads: list[tuple[str, bytes, int]]
) -> dict[str, dict[str, Any]]:
    if os.listdir(parent_fd):
        raise SealedBuildError("attempt-private publication directory is not empty")
    names = [name for name, _, _ in payloads]
    if len(set(names)) != len(names):
        raise SealedBuildError("transactional publication contains duplicate names")
    records: dict[str, dict[str, Any]] = {}
    try:
        for name, content, mode in payloads:
            records[name] = publish_bytes(parent_fd, name, content, mode)
        return records
    except BaseException:
        for name in reversed(names):
            try:
                os.unlink(name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.fsync(parent_fd)
        raise


def rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise SealedBuildError("transactional publication requires renameat2(RENAME_NOREPLACE)")
    result = renameat2(
        ctypes.c_int(-100),
        os.fsencode(source),
        ctypes.c_int(-100),
        os.fsencode(destination),
        ctypes.c_uint(RENAME_NOREPLACE),
    )
    if result != 0:
        error = ctypes.get_errno()
        raise SealedBuildError(
            f"cannot atomically publish sealed build set: {os.strerror(error)}"
        )


def rollback_bound_publication(bound_fd: int, path: Path) -> None:
    try:
        reopened = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return
    try:
        bound = os.fstat(bound_fd)
        current = os.fstat(reopened)
        if (bound.st_dev, bound.st_ino) != (current.st_dev, current.st_ino):
            return
        for name in tuple(os.listdir(bound_fd)):
            try:
                os.unlink(name, dir_fd=bound_fd)
            except FileNotFoundError:
                pass
        os.fsync(bound_fd)
    finally:
        os.close(reopened)
    try:
        os.rmdir(path)
    except FileNotFoundError:
        pass


def inside_build(args: argparse.Namespace) -> int:
    require_linux()
    set_nondumpable()
    workspace = Path(args.workspace)
    workspace.mkdir(mode=0o700)
    mount(None, Path("/"), None, MS_REC | MS_PRIVATE, None)
    mount("tmpfs", workspace, "tmpfs", MS_NOSUID | MS_NODEV, "mode=0700")
    inputs = workspace / "inputs"
    source = inputs / "source"
    toolchain = inputs / "toolchain"
    source.mkdir(parents=True)
    safe_extract(args.bundle_fd, source)
    source_manifest = json.loads(
        (source / ".euf-viper-sealed-source-manifest.json").read_text(encoding="utf-8")
    )
    if sha256_bytes(canonical_bytes(source_manifest)) != args.source_manifest_sha256:
        raise SealedBuildError("extracted source manifest does not match the sealed hash")
    verify_source_snapshot(
        source,
        source_manifest,
        revision=args.revision,
        tree=args.tree,
    )
    copied_toolchain = copy_tree_verified(
        Path(args.sysroot), toolchain, "rust_toolchain"
    )

    native_tools = {
        name: Path(path) for name, path in json.loads(args.native_tools).items()
    }
    environment = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
    discovered = compiler_subtools(native_tools["cc"], "cc", environment)
    discovered.update(compiler_subtools(native_tools["cxx"], "cxx", environment))
    strace = Path(args.strace).resolve(strict=True)
    copied_cargo = (toolchain / "bin" / "cargo").resolve(strict=True)
    copied_rustc = (toolchain / "bin" / "rustc").resolve(strict=True)
    for path in (copied_cargo, copied_rustc):
        try:
            path.relative_to(toolchain.resolve(strict=True))
        except ValueError as error:
            raise SealedBuildError("Rust compiler executable escaped the copied toolchain") from error
    declared_bin = inputs / "native-bin"
    declared_bin.mkdir(mode=0o700)
    declared_tools = {**native_tools, **discovered}
    declared_names: dict[str, Path] = {}
    for path in declared_tools.values():
        name = path.name
        previous = declared_names.get(name)
        if previous is not None and previous != path:
            raise SealedBuildError(f"native tool basename collision for {name}")
        declared_names[name] = path
    for name, path in sorted(declared_names.items()):
        (declared_bin / name).symlink_to(path)
    for read_only in (source, toolchain, declared_bin):
        mount(str(read_only), read_only, None, MS_BIND | MS_REC, None)
        mount(
            None,
            read_only,
            None,
            MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
            None,
        )
        verify_read_only(read_only)

    home = workspace / "home"
    discovery_cargo_home = workspace / "cargo-home-discovery"
    cargo_home = workspace / "cargo-home-production"
    discovery_target = workspace / "target-discovery"
    target = workspace / "target"
    temporary = workspace / "tmp"
    for path in (
        home,
        discovery_cargo_home,
        cargo_home,
        discovery_target,
        target,
        temporary,
    ):
        path.mkdir(mode=0o700)
    base_build_environment = {
        "AR": str(native_tools["ar"]),
        "CC": str(native_tools["cc"]),
        "CARGO_BUILD_JOBS": "1",
        "CXX": str(native_tools["cxx"]),
        "EUF_VIPER_SEALED_GIT_REVISION": args.revision,
        "EUF_VIPER_SEALED_SOURCE_MANIFEST_SHA256": args.source_manifest_sha256,
        "EUF_VIPER_SEALED_SOURCE_TREE": args.tree,
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": f"{toolchain / 'bin'}:{declared_bin}",
        "RANLIB": str(native_tools["ranlib"]),
        "RUSTC": str(copied_rustc),
        "RUSTFLAGS": "-Ctarget-cpu=generic",
        "SOURCE_DATE_EPOCH": str(args.source_date_epoch),
        "TMPDIR": str(temporary),
        "TZ": "UTC",
    }
    cargo_arguments = [
        "build",
        "--locked",
        "--offline",
        "--release",
        "--features",
        args.features,
    ]
    discovery_environment = {
        **base_build_environment,
        "CARGO_HOME": str(discovery_cargo_home),
        "CARGO_TARGET_DIR": str(discovery_target),
        "EUF_VIPER_BUILD_CONTEXT": "sealed-linux-input-discovery-v2",
        "EUF_VIPER_BUILD_EXECUTION_CLOSURE_SHA256": "0" * 64,
    }
    discovery_trace = workspace / "discovery.strace"
    trace_build(
        strace,
        copied_cargo,
        cargo_arguments,
        cwd=source,
        environment=discovery_environment,
        trace=discovery_trace,
        label="sealed build input discovery",
    )
    (
        discovery_paths,
        discovery_directories,
        discovery_virtual,
        discovery_missing,
    ) = traced_paths(discovery_trace)
    discovery_trace_raw = stable_read(discovery_trace, "discovery trace")[0]
    discovery_trace_record = canonical_trace_payload(
        discovery_trace_raw, workspace=workspace, phase="discovery"
    )
    python_runtime = python_runtime_snapshot(Path(args.ldd), environment)
    external_paths = {
        path
        for path in discovery_paths
        if not path_below(path, (workspace.resolve(strict=True),))
    }
    external_paths.update(
        Path(record["path"]) for record in python_runtime["files"]
    )
    external_paths.update(path.resolve(strict=True) for path in declared_tools.values())
    external_paths.update(
        ldd_paths(Path(args.ldd), strace, environment)
    )
    external_paths.update({Path(args.ldd).resolve(strict=True), strace})
    retained_paths = {path: "external_build_input" for path in external_paths}
    for path in discovery_paths:
        if path_below(path, (toolchain.resolve(strict=True),)):
            retained_paths[path] = "rust_toolchain_input"
    retained_paths[copied_cargo] = "rust_toolchain_input"
    retained_paths[copied_rustc] = "rust_toolchain_input"
    retained_archive, retained_index = retained_input_bundle(retained_paths)
    source_bundle = read_sealed_descriptor(args.bundle_fd, "sealed source snapshot")
    workspace_root = workspace.resolve(strict=True)
    external_directories = {
        path
        for path in discovery_directories
        if not path_below(path, (workspace_root,))
    }
    sealed_descriptors: list[int] = []
    native_inputs: list[dict[str, Any]] = []
    directory_inputs: list[dict[str, Any]] = []
    try:
        for path in sorted(external_directories, key=lambda item: (len(item.parts), str(item))):
            directory_inputs.append(directory_record(path))
            mount(str(path), path, None, MS_BIND, None)
            mount(
                None,
                path,
                None,
                MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
                None,
            )
        for path in sorted(external_paths):
            descriptor, record = seal_and_mount_file(path)
            sealed_descriptors.append(descriptor)
            native_inputs.append(record)
        if python_runtime_snapshot(Path(args.ldd), environment) != python_runtime:
            raise SealedBuildError("Python runtime changed while build inputs were sealed")
        closure = {
            "access_discovery": {
                "missing_paths": sorted(discovery_missing),
                "sha256": sha256_bytes(discovery_trace_raw),
                "virtual_paths": sorted(discovery_virtual),
            },
            "external_directories": directory_inputs,
            "external_inputs": native_inputs,
            "policy": "two-pass-all-syscall-trace-sealed-memfd-v2",
            "retained_inputs": {
                "archive_sha256": sha256_bytes(retained_archive),
                "index": retained_index,
                "index_sha256": sha256_bytes(canonical_bytes(retained_index)),
                "source_snapshot_sha256": sha256_bytes(source_bundle),
            },
            "python_runtime": python_runtime,
            "rust_toolchain": copied_toolchain,
            "schema": CLOSURE_SCHEMA,
        }
        closure_bytes = canonical_bytes(closure)
        closure_sha256 = sha256_bytes(closure_bytes)
        (inputs / "build-execution-closure.json").write_bytes(closure_bytes)
        mount(str(inputs), inputs, None, MS_BIND | MS_REC, None)
        mount(
            None,
            inputs,
            None,
            MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
            None,
        )
        verify_read_only(inputs)

        build_environment = {
            **base_build_environment,
            "CARGO_HOME": str(cargo_home),
            "CARGO_TARGET_DIR": str(target),
            "EUF_VIPER_BUILD_CONTEXT": "sealed-linux-production-evidence-v5",
            "EUF_VIPER_BUILD_EXECUTION_CLOSURE_SHA256": closure_sha256,
        }
        actual_trace = workspace / "actual.strace"
        trace_build(
            strace,
            copied_cargo,
            cargo_arguments,
            cwd=source,
            environment=build_environment,
            trace=actual_trace,
            label="sealed cargo build",
        )
        actual_paths, actual_directories, actual_virtual, actual_missing = traced_paths(
            actual_trace
        )
        actual_trace_raw = stable_read(actual_trace, "actual build trace")[0]
        actual_trace_record = canonical_trace_payload(
            actual_trace_raw, workspace=workspace, phase="production"
        )
        unexpected = sorted(
            path
            for path in actual_paths
            if not path_below(path, (workspace.resolve(strict=True),))
            and path not in external_paths
        )
        if unexpected:
            raise SealedBuildError(
                "actual build accessed inputs absent from discovery: "
                + ", ".join(str(path) for path in unexpected[:8])
            )
        unexpected_directories = sorted(
            path
            for path in actual_directories
            if not path_below(path, (workspace_root,))
            and path not in external_directories
        )
        if unexpected_directories:
            raise SealedBuildError(
                "actual build accessed directories absent from discovery: "
                + ", ".join(str(path) for path in unexpected_directories[:8])
            )
        unexpected_missing = sorted(actual_missing - discovery_missing)
        if unexpected_missing:
            raise SealedBuildError(
                "actual build attempted absent paths missing from discovery: "
                + ", ".join(unexpected_missing[:8])
            )
        unexpected_virtual = sorted(actual_virtual - discovery_virtual)
        if unexpected_virtual:
            raise SealedBuildError(
                "actual build accessed virtual paths absent from discovery: "
                + ", ".join(unexpected_virtual[:8])
            )
        for record in native_inputs:
            content, metadata = stable_read(
                Path(record["path"]), "sealed build input after compilation"
            )
            if (
                metadata.st_size != record["bytes"]
                or sha256_bytes(content) != record["sha256"]
            ):
                raise SealedBuildError(
                    f"sealed build input drifted: {record['path']}"
                )
        for expected in directory_inputs:
            if directory_record(Path(expected["path"])) != expected:
                raise SealedBuildError(
                    f"sealed build directory drifted: {expected['path']}"
                )
        if python_runtime_snapshot(Path(args.ldd), environment) != python_runtime:
            raise SealedBuildError("Python runtime changed during the sealed build")
        execution_verification = {
            "actual_trace_sha256": sha256_bytes(actual_trace_raw),
            "canonical_trace_sha256": "",
            "external_directory_count": len(directory_inputs),
            "external_input_count": len(native_inputs),
            "status": "accepted",
            "unexpected_external_inputs": [],
            "virtual_paths": sorted(actual_virtual),
        }
    finally:
        for descriptor in sealed_descriptors:
            os.close(descriptor)

    binary_paths = {
        "euf-viper": target / "release" / "euf-viper",
        "euf-viper-build-features": target / "release" / "euf-viper-build-features",
    }
    binary_contents: dict[str, bytes] = {}
    artifacts: dict[str, dict[str, Any]] = {}
    for name, path in binary_paths.items():
        content, metadata = stable_read(path, f"built artifact {name}")
        if not os.access(path, os.X_OK):
            raise SealedBuildError(f"built artifact is not executable: {path}")
        binary_contents[name] = content
        artifacts[name] = {
            "bytes": metadata.st_size,
            "name": name,
            "sha256": sha256_bytes(content),
        }

    canonical_traces = {
        "discovery": discovery_trace_record,
        "namespace": {"network": "isolated", "root": "private-mount-namespace"},
        "production": actual_trace_record,
        "recipe": {
            "arguments": cargo_arguments,
            "environment": build_environment,
            "features": args.features,
            "strace": ["-f", "-qq", "-yy", "-xx", "-v", "-s65535", "trace=all"],
        },
        "schema": TRACE_SET_SCHEMA,
    }
    canonical_trace_bytes = canonical_bytes(canonical_traces)
    execution_verification["canonical_trace_sha256"] = sha256_bytes(
        canonical_trace_bytes
    )

    payload = {
        "schema": SCHEMA,
        "status": "built",
        "artifacts": artifacts,
        "build_execution_closure": closure,
        "build_execution_closure_sha256": closure_sha256,
        "build_execution_verification": execution_verification,
        "revision": args.revision,
        "source_snapshot": source_manifest,
        "source_snapshot_manifest_sha256": args.source_manifest_sha256,
        "source_tree": args.tree,
        "toolchain": args.toolchain,
    }
    publish_build_set(
        args.output_fd,
        [
            ("euf-viper", binary_contents["euf-viper"], 0o500),
            (
                "euf-viper-build-features",
                binary_contents["euf-viper-build-features"],
                0o500,
            ),
            ("sealed-build-manifest.json", canonical_bytes(payload), 0o400),
            ("sealed-source-snapshot.tar", source_bundle, 0o400),
            ("retained-build-inputs.tar", retained_archive, 0o400),
            (
                "retained-build-inputs.json",
                canonical_bytes(retained_index),
                0o400,
            ),
            ("build-discovery.strace", discovery_trace_raw, 0o400),
            ("build-production.strace", actual_trace_raw, 0o400),
            ("canonical-build-traces.json", canonical_trace_bytes, 0o400),
        ],
    )
    return 0


def pinned_toolchain_channel(
    records: list[tuple[str, bytes, int, str]],
) -> str:
    matches = [content for path, content, _, _ in records if path == "rust-toolchain.toml"]
    if len(matches) != 1:
        raise SealedBuildError("exact Git snapshot must contain one rust-toolchain.toml")
    try:
        pin = tomllib.loads(matches[0].decode("ascii"))["toolchain"]
    except (UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise SealedBuildError("exact Git snapshot has an invalid toolchain pin") from error
    if (
        type(pin) is not dict
        or set(pin) != {"channel", "components", "profile"}
        or pin.get("profile") != "minimal"
        or pin.get("components") != ["rustfmt"]
    ):
        raise SealedBuildError("toolchain pin must use minimal profile and pinned rustfmt")
    expected = pin.get("channel")
    if (
        type(expected) is not str
        or len(expected.split(".")) != 3
        or not all(part.isdigit() for part in expected.split("."))
    ):
        raise SealedBuildError("Rust toolchain channel must be an exact numeric release")
    return expected


def toolchain_pin(
    expected: str,
    rustc: Path,
    cargo: Path,
    environment: dict[str, str],
) -> tuple[dict[str, str], Path]:
    rustc_output = require_success(
        stable_command(rustc, ["-Vv"], environment=environment), "rustc version"
    ).decode("utf-8", "strict")
    release = next(
        (line.partition(":")[2].strip() for line in rustc_output.splitlines() if line.startswith("release:")),
        None,
    )
    cargo_output = require_success(
        stable_command(cargo, ["-V"], environment=environment), "cargo version"
    ).decode("utf-8", "strict").strip()
    if release != expected or not cargo_output.startswith(f"cargo {expected} "):
        raise SealedBuildError(
            f"toolchain pin mismatch: expected {expected}, rustc={release}, cargo={cargo_output!r}"
        )
    sysroot_raw = require_success(
        stable_command(rustc, ["--print", "sysroot"], environment=environment),
        "rustc sysroot",
    ).decode("utf-8", "strict").strip()
    sysroot = Path(sysroot_raw).resolve(strict=True)
    return {"cargo": cargo_output, "rustc": rustc_output.strip()}, sysroot


def stable_read_at(parent_fd: int, name: str, label: str) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SealedBuildError(f"{label} is not a regular file")
        digest = bytearray()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.extend(block)
        after = os.fstat(descriptor)
        if fingerprint(before) != fingerprint(after) or len(digest) != after.st_size:
            raise SealedBuildError(f"{label} changed while it was verified")
        return bytes(digest), after
    finally:
        os.close(descriptor)


def verify_published_build(
    bound_directory: int,
    artifact_dir: Path,
    *,
    revision: str,
    tree: str,
    source_manifest_sha256: str,
    toolchain: dict[str, str],
    attestor_sha256: str | None = None,
    attestation_sha256: str | None = None,
    receipt_sha256: str | None = None,
) -> dict[str, Any]:
    rebound_directory = os.open(
        artifact_dir,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        bound = os.fstat(bound_directory)
        rebound = os.fstat(rebound_directory)
        if (
            bound.st_dev,
            bound.st_ino,
            bound.st_mode,
            bound.st_uid,
            bound.st_gid,
        ) != (
            rebound.st_dev,
            rebound.st_ino,
            rebound.st_mode,
            rebound.st_uid,
            rebound.st_gid,
        ):
            raise SealedBuildError("artifact directory path changed during publication")
        expected_names = {
            "build-discovery.strace",
            "build-production.strace",
            "canonical-build-traces.json",
            "euf-viper",
            "euf-viper-build-features",
            "retained-build-inputs.json",
            "retained-build-inputs.tar",
            "sealed-build-manifest.json",
            "sealed-source-snapshot.tar",
        }
        if receipt_sha256 is not None:
            expected_names.add("sealed-build-receipt.json")
        if attestation_sha256 is not None:
            expected_names.add("sealed-build-attestation.json")
        if set(os.listdir(bound_directory)) != expected_names:
            raise SealedBuildError("artifact directory contains an unbound entry")
        manifest_raw, manifest_metadata = stable_read_at(
            bound_directory,
            "sealed-build-manifest.json",
            "sealed build manifest",
        )
        rebound_raw, rebound_metadata = stable_read_at(
            rebound_directory,
            "sealed-build-manifest.json",
            "reopened sealed build manifest",
        )
        if (
            fingerprint(manifest_metadata) != fingerprint(rebound_metadata)
            or manifest_raw != rebound_raw
        ):
            raise SealedBuildError("sealed build manifest changed across parent reopen")
        try:
            manifest = json.loads(manifest_raw)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise SealedBuildError("sealed build returned invalid JSON") from error
        if canonical_bytes(manifest) != manifest_raw:
            raise SealedBuildError("sealed build manifest is not canonical JSON")
        if stat.S_IMODE(manifest_metadata.st_mode) != 0o400:
            raise SealedBuildError("sealed build manifest mode differs")
        if (
            manifest.get("schema") != SCHEMA
            or manifest.get("status") != "built"
            or manifest.get("revision") != revision
            or manifest.get("source_tree") != tree
            or manifest.get("source_snapshot_manifest_sha256")
            != source_manifest_sha256
            or manifest.get("toolchain") != toolchain
            or set(manifest.get("artifacts", {}))
            != {"euf-viper", "euf-viper-build-features"}
        ):
            raise SealedBuildError("sealed build returned an invalid binding manifest")
        closure = manifest.get("build_execution_closure")
        if (
            type(closure) is not dict
            or closure.get("schema") != CLOSURE_SCHEMA
            or sha256_bytes(canonical_bytes(closure))
            != manifest.get("build_execution_closure_sha256")
        ):
            raise SealedBuildError("sealed build execution closure binding is invalid")
        verification = manifest.get("build_execution_verification")
        if (
            type(verification) is not dict
            or set(verification)
            != {
                "actual_trace_sha256",
                "canonical_trace_sha256",
                "external_directory_count",
                "external_input_count",
                "status",
                "unexpected_external_inputs",
                "virtual_paths",
            }
            or verification.get("status") != "accepted"
            or verification.get("unexpected_external_inputs") != []
            or type(verification.get("external_input_count")) is not int
            or verification["external_input_count"]
            != len(closure.get("external_inputs", []))
            or verification["external_directory_count"]
            != len(closure.get("external_directories", []))
        ):
            raise SealedBuildError("sealed build execution verification is invalid")
        verified_files: dict[str, tuple[bytes, tuple[int, ...]]] = {
            "sealed-build-manifest.json": (
                manifest_raw,
                fingerprint(manifest_metadata),
            )
        }
        retained = closure.get("retained_inputs")
        if type(retained) is not dict or set(retained) != {
            "archive_sha256",
            "index",
            "index_sha256",
            "source_snapshot_sha256",
        }:
            raise SealedBuildError("retained build-input closure is malformed")
        auxiliary_expectations = {
            "build-discovery.strace": closure["access_discovery"]["sha256"],
            "build-production.strace": verification["actual_trace_sha256"],
            "canonical-build-traces.json": verification[
                "canonical_trace_sha256"
            ],
            "retained-build-inputs.json": retained["index_sha256"],
            "retained-build-inputs.tar": retained["archive_sha256"],
            "sealed-source-snapshot.tar": retained["source_snapshot_sha256"],
        }
        for name, expected_sha256 in auxiliary_expectations.items():
            content, metadata = stable_read_at(
                bound_directory, name, f"sealed auxiliary artifact {name}"
            )
            if (
                sha256_bytes(content) != expected_sha256
                or stat.S_IMODE(metadata.st_mode) != 0o400
            ):
                raise SealedBuildError(f"sealed auxiliary artifact differs: {name}")
            verified_files[name] = (content, fingerprint(metadata))
        index_raw = verified_files["retained-build-inputs.json"][0]
        if index_raw != canonical_bytes(retained["index"]):
            raise SealedBuildError("retained build-input index differs from manifest")
        for name, record in manifest["artifacts"].items():
            content, metadata = stable_read_at(
                bound_directory, name, f"sealed artifact {name}"
            )
            reopened_content, reopened_metadata = stable_read_at(
                rebound_directory, name, f"reopened sealed artifact {name}"
            )
            expected = {
                "bytes": metadata.st_size,
                "name": name,
                "sha256": sha256_bytes(content),
            }
            if (
                record != expected
                or stat.S_IMODE(metadata.st_mode) != 0o500
                or fingerprint(metadata) != fingerprint(reopened_metadata)
                or content != reopened_content
            ):
                raise SealedBuildError(f"sealed artifact binding mismatch for {name}")
            verified_files[name] = (content, fingerprint(metadata))
        os.fsync(bound_directory)
        final_directory = os.open(
            artifact_dir,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            if (os.fstat(bound_directory).st_dev, os.fstat(bound_directory).st_ino) != (
                os.fstat(final_directory).st_dev,
                os.fstat(final_directory).st_ino,
            ):
                raise SealedBuildError("artifact directory changed during final sync")
            if set(os.listdir(final_directory)) != expected_names:
                raise SealedBuildError("artifact directory changed during final sync")
            for name, (expected_content, expected_fingerprint) in verified_files.items():
                content, metadata = stable_read_at(
                    final_directory, name, f"final sealed artifact {name}"
                )
                bound_content, bound_metadata = stable_read_at(
                    bound_directory, name, f"bound sealed artifact {name}"
                )
                if (
                    content != expected_content
                    or bound_content != expected_content
                    or fingerprint(metadata) != expected_fingerprint
                    or fingerprint(bound_metadata) != expected_fingerprint
                ):
                    raise SealedBuildError(
                        f"sealed artifact changed during final directory sync: {name}"
                    )
        finally:
            os.close(final_directory)
        result = {
            "artifacts": manifest["artifacts"],
            "manifest": str(artifact_dir / "sealed-build-manifest.json"),
            "manifest_sha256": sha256_bytes(manifest_raw),
            "source_snapshot_manifest_sha256": source_manifest_sha256,
            "status": "built",
        }
        if attestation_sha256 is not None:
            attestation_raw, attestation_metadata = stable_read_at(
                bound_directory,
                "sealed-build-attestation.json",
                "independent sealed build attestation",
            )
            if (
                sha256_bytes(attestation_raw) != attestation_sha256
                or stat.S_IMODE(attestation_metadata.st_mode) != 0o400
            ):
                raise SealedBuildError("independent sealed build attestation differs")
            try:
                attestation = json.loads(attestation_raw)
            except (UnicodeError, json.JSONDecodeError) as error:
                raise SealedBuildError("independent attestation is invalid JSON") from error
            if (
                canonical_bytes(attestation) != attestation_raw
                or attestation.get("schema") != ATTESTATION_SCHEMA
                or attestation.get("status") != "accepted"
                or attestation.get("attestor_sha256") != attestor_sha256
                or attestation.get("build_manifest_sha256")
                != sha256_bytes(manifest_raw)
                or attestation.get("artifacts")
                != {
                    name: {
                        "bytes": record["bytes"],
                        "mode": "0500",
                        "sha256": record["sha256"],
                    }
                    for name, record in manifest["artifacts"].items()
                }
            ):
                raise SealedBuildError("independent attestation bindings differ")
            result["attestation"] = str(
                artifact_dir / "sealed-build-attestation.json"
            )
            result["attestation_sha256"] = attestation_sha256
        if receipt_sha256 is not None:
            receipt_raw, receipt_metadata = stable_read_at(
                bound_directory,
                "sealed-build-receipt.json",
                "external sealed build receipt",
            )
            reopened_receipt, reopened_receipt_metadata = stable_read_at(
                rebound_directory,
                "sealed-build-receipt.json",
                "reopened external sealed build receipt",
            )
            if sha256_bytes(receipt_raw) != receipt_sha256:
                raise SealedBuildError("external sealed build receipt SHA-256 differs")
            if stat.S_IMODE(receipt_metadata.st_mode) != 0o400:
                raise SealedBuildError("external sealed build receipt mode differs")
            if (
                receipt_raw != reopened_receipt
                or fingerprint(receipt_metadata)
                != fingerprint(reopened_receipt_metadata)
            ):
                raise SealedBuildError("external sealed build receipt changed across reopen")
            try:
                receipt = json.loads(receipt_raw)
            except (UnicodeError, json.JSONDecodeError) as error:
                raise SealedBuildError("external sealed build receipt is invalid JSON") from error
            if canonical_bytes(receipt) != receipt_raw:
                raise SealedBuildError("external sealed build receipt is not canonical")
            if receipt != create_external_receipt(
                bound_directory, expected_attestor_sha256=attestor_sha256
            ):
                raise SealedBuildError("external sealed build receipt binding differs")
            os.fsync(bound_directory)
            final_receipt_directory = os.open(
                artifact_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            try:
                final_receipt, final_receipt_metadata = stable_read_at(
                    final_receipt_directory,
                    "sealed-build-receipt.json",
                    "final external sealed build receipt",
                )
                if (
                    final_receipt != receipt_raw
                    or fingerprint(final_receipt_metadata)
                    != fingerprint(receipt_metadata)
                ):
                    raise SealedBuildError(
                        "external sealed build receipt changed during final sync"
                    )
            finally:
                os.close(final_receipt_directory)
            result["receipt"] = str(artifact_dir / "sealed-build-receipt.json")
            result["receipt_sha256"] = receipt_sha256
        return result
    finally:
        os.close(rebound_directory)


def execute_published(parent_fd: int, name: str) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        completed = subprocess.run(
            [f"/proc/self/fd/{descriptor}"],
            capture_output=True,
            check=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            pass_fds=(descriptor,),
            stdin=subprocess.DEVNULL,
        )
    finally:
        os.close(descriptor)
    return require_success(completed, f"published executable {name}")


def create_external_receipt(
    parent_fd: int, *, expected_attestor_sha256: str | None = None
) -> dict[str, Any]:
    manifest_raw, _ = stable_read_at(
        parent_fd, "sealed-build-manifest.json", "sealed build manifest"
    )
    try:
        manifest = json.loads(manifest_raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SealedBuildError("sealed build manifest is invalid JSON") from error
    if canonical_bytes(manifest) != manifest_raw:
        raise SealedBuildError("sealed build manifest is not canonical JSON")
    feature_output = execute_published(parent_fd, "euf-viper-build-features").decode(
        "ascii", "strict"
    ).strip()
    features = feature_output.split(",") if feature_output else []
    if (
        not features
        or features != sorted(set(features))
        or "production-evidence" not in features
    ):
        raise SealedBuildError("feature-report executable returned an invalid feature set")
    rustc = manifest.get("toolchain", {}).get("rustc", "")
    target = next(
        (
            line.partition(":")[2].strip()
            for line in rustc.splitlines()
            if line.startswith("host:")
        ),
        None,
    )
    if not target or "linux" not in target:
        raise SealedBuildError("sealed toolchain does not identify a Linux target")
    artifacts: dict[str, dict[str, Any]] = {}
    for name in ("euf-viper", "euf-viper-build-features"):
        content, metadata = stable_read_at(parent_fd, name, f"receipt artifact {name}")
        if stat.S_IMODE(metadata.st_mode) != 0o500:
            raise SealedBuildError(f"sealed artifact mode differs before receipt: {name}")
        record = manifest.get("artifacts", {}).get(name)
        expected = {
            "bytes": metadata.st_size,
            "name": name,
            "sha256": sha256_bytes(content),
        }
        if record != expected:
            raise SealedBuildError(f"sealed artifact changed before receipt: {name}")
        artifacts[name] = {
            "bytes": metadata.st_size,
            "mode": "0500",
            "sha256": expected["sha256"],
        }
    attestation_raw, attestation_metadata = stable_read_at(
        parent_fd,
        "sealed-build-attestation.json",
        "independent sealed build attestation",
    )
    try:
        attestation = json.loads(attestation_raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SealedBuildError("independent attestation is invalid JSON") from error
    if (
        canonical_bytes(attestation) != attestation_raw
        or stat.S_IMODE(attestation_metadata.st_mode) != 0o400
        or attestation.get("schema") != ATTESTATION_SCHEMA
        or attestation.get("status") != "accepted"
        or (
            expected_attestor_sha256 is not None
            and attestation.get("attestor_sha256") != expected_attestor_sha256
        )
        or attestation.get("build_manifest_sha256") != sha256_bytes(manifest_raw)
        or attestation.get("artifacts") != artifacts
        or attestation.get("features") != features
        or attestation.get("closure_sha256")
        != manifest["build_execution_closure_sha256"]
    ):
        raise SealedBuildError("independent attestation differs before receipt")
    return {
        "artifacts": artifacts,
        "build": {
            "execution_closure_sha256": manifest["build_execution_closure_sha256"],
            "features": features,
            "profile": "release",
            "target": target,
            "toolchain": manifest["toolchain"],
        },
        "independent_attestation": attestation,
        "schema": RECEIPT_SCHEMA,
        "sealed_build_manifest_sha256": sha256_bytes(manifest_raw),
        "source": {
            "dirty": False,
            "revision": manifest["revision"],
            "snapshot_manifest_sha256": manifest[
                "source_snapshot_manifest_sha256"
            ],
            "tree": manifest["source_tree"],
        },
        "status": "accepted",
    }


def outer_build(args: argparse.Namespace) -> int:
    require_linux()
    repository = args.repository.resolve(strict=True)
    artifact_dir = args.artifact_dir.absolute()
    artifact_parent = artifact_dir.parent
    artifact_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    artifact_parent = require_private_directory(
        artifact_parent, "artifact publication parent"
    )
    if os.path.lexists(artifact_dir):
        raise SealedBuildError("sealed build destination must not exist")
    attestor_path = args.attestor.resolve(strict=True)
    attestor_content, _ = stable_read(attestor_path, "independent build attestor")
    if sha256_bytes(attestor_content) != args.attestor_sha256:
        raise SealedBuildError("independent build attestor SHA-256 differs")

    tools = {
        "git": checked_executable(args.git, "git"),
        "cargo": checked_executable(args.cargo, "cargo"),
        "rustc": checked_executable(args.rustc, "rustc"),
        "unshare": checked_executable(args.unshare, "unshare"),
        "ldd": checked_executable(args.ldd, "ldd"),
        "cc": checked_executable(args.cc, "cc"),
        "cxx": checked_executable(args.cxx, "cxx"),
        "ar": checked_executable(args.ar, "ar"),
        "ranlib": checked_executable(args.ranlib, "ranlib"),
        "strace": checked_executable(args.strace, "strace"),
    }
    environment = {
        "CARGO_HOME": str(args.cargo_home.resolve()),
        "HOME": str(args.home.resolve()),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", os.defpath),
        "RUSTUP_HOME": str(args.rustup_home.resolve()),
        "TZ": "UTC",
    }
    tree = require_success(
        stable_command(
            tools["git"],
            ["-C", str(repository), "rev-parse", f"{args.revision}^{{tree}}"],
            environment=environment,
        ),
        "Git tree lookup",
    ).decode("ascii").strip()
    source_date_raw = require_success(
        stable_command(
            tools["git"],
            [
                "-C",
                str(repository),
                "show",
                "-s",
                "--format=%ct",
                args.revision,
            ],
            environment=environment,
        ),
        "Git commit timestamp lookup",
    ).decode("ascii").strip()
    if not source_date_raw.isdigit():
        raise SealedBuildError("Git commit timestamp is not a positive integer")
    source_date_epoch = int(source_date_raw)

    staging_parent = args.staging_root.absolute()
    staging_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging_parent = require_private_directory(staging_parent, "sealed staging root")
    records = git_snapshot(repository, args.revision, tools["git"], environment)
    expected_toolchain = pinned_toolchain_channel(records)
    toolchain, sysroot = toolchain_pin(
        expected_toolchain,
        tools["rustc"],
        tools["cargo"],
        environment,
    )
    with tempfile.TemporaryDirectory(prefix="sealed-vendor-", dir=staging_parent) as raw_vendor:
        vendor_source = Path(raw_vendor) / "source"
        materialize_git_snapshot(records, vendor_source)
        vendor = Path(raw_vendor) / "registry"
        completed = stable_command(
            tools["cargo"],
            ["vendor", "--locked", "--versioned-dirs", str(vendor)],
            environment=environment,
            cwd=vendor_source,
        )
        require_success(completed, "cargo vendor --locked")
        config = (
            b"[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n"
            b"[source.vendored-sources]\ndirectory = \"vendor-registry\"\n\n"
            b"[net]\noffline = true\n"
        )
        records.extend(vendor_snapshot(vendor))
        records.append((".cargo/config.toml", config, 0o444, "generated_cargo_config"))
        records.sort(key=lambda item: item[0])
        bundle_fd, _, source_manifest_sha256 = sealed_bundle(records, args.revision, tree)

        attempt = Path(
            tempfile.mkdtemp(
                prefix=f".{artifact_dir.name}.attempt-", dir=artifact_parent
            )
        )
        output_fd = os.open(attempt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        script_content, script_metadata = current_helper_bytes()
        script_fd = sealed_content_descriptor(
            "build-helper", script_content, stat.S_IMODE(script_metadata.st_mode)
        )
        python_path = checked_executable(Path(sys.executable), "Python")
        python_fd, python_descriptor_sha256 = open_verified_descriptor(
            python_path, "Python executable"
        )
        unshare_fd, unshare_descriptor_sha256 = open_verified_descriptor(
            tools["unshare"], "unshare executable"
        )
        attestor_fd = sealed_content_descriptor(
            "build-attestor", attestor_content, 0o400
        )
        workspace = staging_parent / f"namespace-{os.getpid()}"
        published_final = False
        publication_complete = False
        try:
            native = {name: str(tools[name]) for name in ("cc", "cxx", "ar", "ranlib")}
            set_nondumpable()
            command = [
                f"/proc/self/fd/{unshare_fd}",
                "--user",
                "--map-root-user",
                "--mount",
                "--net",
                "--fork",
                "--",
                f"/proc/self/fd/{python_fd}",
                "-B",
                "-I",
                "-S",
                f"/proc/self/fd/{script_fd}",
                "_inside",
                "--bundle-fd",
                str(bundle_fd),
                "--output-fd",
                str(output_fd),
                "--workspace",
                str(workspace),
                "--sysroot",
                str(sysroot),
                "--ldd",
                str(tools["ldd"]),
                "--strace",
                str(tools["strace"]),
                "--native-tools",
                json.dumps(native, sort_keys=True, separators=(",", ":")),
                "--revision",
                args.revision,
                "--tree",
                tree,
                "--source-manifest-sha256",
                source_manifest_sha256,
                "--source-date-epoch",
                str(source_date_epoch),
                "--features",
                args.features,
                "--toolchain",
                json.dumps(toolchain, sort_keys=True, separators=(",", ":")),
            ]
            completed = subprocess.run(
                command,
                capture_output=True,
                check=False,
                pass_fds=(
                    bundle_fd,
                    output_fd,
                    script_fd,
                    python_fd,
                    unshare_fd,
                ),
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                stdin=subprocess.DEVNULL,
            )
            require_success(completed, "sealed Linux namespace build")
            reverify_open_descriptor(
                python_fd, python_descriptor_sha256, "Python executable"
            )
            reverify_open_descriptor(
                unshare_fd, unshare_descriptor_sha256, "unshare executable"
            )
            verify_published_build(
                output_fd,
                attempt,
                revision=args.revision,
                tree=tree,
                source_manifest_sha256=source_manifest_sha256,
                toolchain=toolchain,
            )
            attestation_process = subprocess.run(
                [
                    f"/proc/self/fd/{python_fd}",
                    "-B",
                    "-I",
                    "-S",
                    f"/proc/self/fd/{attestor_fd}",
                    "create",
                    "--artifact-dir-fd",
                    str(output_fd),
                ],
                capture_output=True,
                check=False,
                pass_fds=(python_fd, attestor_fd, output_fd),
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                stdin=subprocess.DEVNULL,
            )
            attestation_bytes = require_success(
                attestation_process, "independent sealed build attestation"
            )
            published_attestation, _ = stable_read_at(
                output_fd,
                "sealed-build-attestation.json",
                "published independent attestation",
            )
            if published_attestation != attestation_bytes:
                raise SealedBuildError("attestor output differs from published bytes")
            attestation_sha256 = sha256_bytes(attestation_bytes)
            verify_published_build(
                output_fd,
                attempt,
                revision=args.revision,
                tree=tree,
                source_manifest_sha256=source_manifest_sha256,
                toolchain=toolchain,
                attestor_sha256=args.attestor_sha256,
                attestation_sha256=attestation_sha256,
            )
            receipt_bytes = canonical_bytes(
                create_external_receipt(
                    output_fd, expected_attestor_sha256=args.attestor_sha256
                )
            )
            receipt_sha256 = sha256_bytes(receipt_bytes)
            publish_bytes(
                output_fd, "sealed-build-receipt.json", receipt_bytes, 0o400
            )
            verify_published_build(
                output_fd,
                attempt,
                revision=args.revision,
                tree=tree,
                source_manifest_sha256=source_manifest_sha256,
                toolchain=toolchain,
                attestor_sha256=args.attestor_sha256,
                attestation_sha256=attestation_sha256,
                receipt_sha256=receipt_sha256,
            )
            rename_noreplace(attempt, artifact_dir)
            published_final = True
            parent_fd = os.open(
                artifact_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            summary = verify_published_build(
                output_fd,
                artifact_dir,
                revision=args.revision,
                tree=tree,
                source_manifest_sha256=source_manifest_sha256,
                toolchain=toolchain,
                attestor_sha256=args.attestor_sha256,
                attestation_sha256=attestation_sha256,
                receipt_sha256=receipt_sha256,
            )
            final_attestation = subprocess.run(
                [
                    f"/proc/self/fd/{python_fd}",
                    "-B",
                    "-I",
                    "-S",
                    f"/proc/self/fd/{attestor_fd}",
                    "verify",
                    "--artifact-dir-fd",
                    str(output_fd),
                ],
                capture_output=True,
                check=False,
                pass_fds=(python_fd, attestor_fd, output_fd),
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                stdin=subprocess.DEVNULL,
            )
            if require_success(
                final_attestation, "final independent sealed build attestation"
            ) != attestation_bytes:
                raise SealedBuildError("final independent attestation reconstruction differs")
            reverify_open_descriptor(
                python_fd, python_descriptor_sha256, "Python executable"
            )
            reverify_open_descriptor(
                unshare_fd, unshare_descriptor_sha256, "unshare executable"
            )
            publication_complete = True
        finally:
            if published_final and not publication_complete:
                rollback_bound_publication(output_fd, artifact_dir)
            for descriptor in (
                bundle_fd,
                output_fd,
                script_fd,
                python_fd,
                unshare_fd,
                attestor_fd,
            ):
                os.close(descriptor)
            if workspace.exists():
                workspace.rmdir()
            if attempt.exists():
                shutil.rmtree(attempt)

    print(canonical_bytes(summary).decode("utf-8"), end="")
    return 0


def probe_inside(args: argparse.Namespace) -> int:
    require_linux()
    set_nondumpable()
    workspace = Path(args.workspace)
    workspace.mkdir(mode=0o700)
    mount(None, Path("/"), None, MS_REC | MS_PRIVATE, None)
    mount("tmpfs", workspace, "tmpfs", MS_NOSUID | MS_NODEV, "mode=0700")
    inputs = workspace / "inputs"
    inputs.mkdir(mode=0o700)
    (inputs / "probe").write_bytes(b"read only\n")
    mount(str(inputs), inputs, None, MS_BIND | MS_REC, None)
    mount(
        None,
        inputs,
        None,
        MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
        None,
    )
    verify_read_only(inputs)
    return 0


def probe(args: argparse.Namespace) -> int:
    require_linux()
    staging = args.staging_root.absolute()
    staging.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging = require_private_directory(staging, "sealed probe root")
    descriptor, _, _ = sealed_bundle(
        [("probe.txt", b"sealed\n", 0o444, "probe")], "0" * 40, "0" * 40
    )
    try:
        try:
            os.write(descriptor, b"attack")
        except OSError:
            pass
        else:
            raise SealedBuildError("sealed memfd accepted a same-UID write")
    finally:
        os.close(descriptor)
    unshare = checked_executable(args.unshare, "unshare")
    python_path = checked_executable(Path(sys.executable), "Python")
    unshare_fd = os.open(unshare, os.O_RDONLY | os.O_NOFOLLOW)
    python_fd = os.open(python_path, os.O_RDONLY | os.O_NOFOLLOW)
    script_content, script_metadata = current_helper_bytes()
    script_fd = sealed_content_descriptor(
        "probe-helper", script_content, stat.S_IMODE(script_metadata.st_mode)
    )
    workspace = staging / f"probe-namespace-{os.getpid()}"
    try:
        set_nondumpable()
        completed = subprocess.run(
            [
                f"/proc/self/fd/{unshare_fd}",
                "--user",
                "--map-root-user",
                "--mount",
                "--net",
                "--fork",
                "--",
                f"/proc/self/fd/{python_fd}",
                "-B",
                "-I",
                "-S",
                f"/proc/self/fd/{script_fd}",
                "_probe_inside",
                "--workspace",
                str(workspace),
            ],
            capture_output=True,
            check=False,
            pass_fds=(unshare_fd, python_fd, script_fd),
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
        require_success(completed, "sealed Linux namespace probe")
    finally:
        for item in (unshare_fd, python_fd, script_fd):
            os.close(item)
        if workspace.exists():
            workspace.rmdir()
    print("sealed Linux build prerequisites available")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--repository", type=Path, required=True)
    build.add_argument("--revision", required=True)
    build.add_argument("--artifact-dir", type=Path, required=True)
    build.add_argument("--staging-root", type=Path, required=True)
    build.add_argument("--cargo-home", type=Path, required=True)
    build.add_argument("--rustup-home", type=Path, required=True)
    build.add_argument("--home", type=Path, required=True)
    build.add_argument("--git", type=Path, required=True)
    build.add_argument("--cargo", type=Path, required=True)
    build.add_argument("--rustc", type=Path, required=True)
    build.add_argument("--unshare", type=Path, required=True)
    build.add_argument("--ldd", type=Path, required=True)
    build.add_argument("--cc", type=Path, required=True)
    build.add_argument("--cxx", type=Path, required=True)
    build.add_argument("--ar", type=Path, required=True)
    build.add_argument("--ranlib", type=Path, required=True)
    build.add_argument("--strace", type=Path, required=True)
    build.add_argument("--attestor", type=Path, required=True)
    build.add_argument("--attestor-sha256", required=True)
    build.add_argument(
        "--features", default="certificates,production-evidence"
    )
    inside = subparsers.add_parser("_inside")
    inside.add_argument("--bundle-fd", type=int, required=True)
    inside.add_argument("--output-fd", type=int, required=True)
    inside.add_argument("--workspace", required=True)
    inside.add_argument("--sysroot", required=True)
    inside.add_argument("--ldd", required=True)
    inside.add_argument("--strace", required=True)
    inside.add_argument("--native-tools", required=True)
    inside.add_argument("--revision", required=True)
    inside.add_argument("--tree", required=True)
    inside.add_argument("--source-manifest-sha256", required=True)
    inside.add_argument("--source-date-epoch", type=int, required=True)
    inside.add_argument("--features", required=True)
    inside.add_argument("--toolchain", type=json.loads, required=True)
    probe_inside_parser = subparsers.add_parser("_probe_inside")
    probe_inside_parser.add_argument("--workspace", required=True)
    check = subparsers.add_parser("probe")
    check.add_argument("--staging-root", type=Path, required=True)
    check.add_argument("--unshare", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "build":
            return outer_build(args)
        if args.command == "_inside":
            return inside_build(args)
        if args.command == "_probe_inside":
            return probe_inside(args)
        return probe(args)
    except (OSError, SealedBuildError, subprocess.SubprocessError, KeyError, ValueError) as error:
        print(f"sealed build rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
