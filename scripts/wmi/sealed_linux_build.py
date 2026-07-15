#!/usr/bin/env python3
"""Build production evidence from a sealed Linux source/toolchain snapshot."""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA = "euf-viper.sealed-linux-build.v1"
SOURCE_SCHEMA = "euf-viper.sealed-source-snapshot.v1"
CLOSURE_SCHEMA = "euf-viper.build-execution-closure.v1"
HEX_REVISION = frozenset("0123456789abcdef")
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
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
    descriptor = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        command = [f"/proc/self/fd/{descriptor}", *arguments]
        return subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            input=input_bytes,
            capture_output=True,
            check=False,
            pass_fds=(descriptor,),
        )
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
    shutil.copytree(Path(args.sysroot), toolchain, symlinks=True)
    validate_internal_symlinks(toolchain)

    native_tools = {
        name: Path(path) for name, path in json.loads(args.native_tools).items()
    }
    environment = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
    discovered = compiler_subtools(native_tools["cc"], "cc", environment)
    discovered.update(compiler_subtools(native_tools["cxx"], "cxx", environment))
    copied_cargo = (toolchain / "bin" / "cargo").resolve(strict=True)
    copied_rustc = (toolchain / "bin" / "rustc").resolve(strict=True)
    for path in (copied_cargo, copied_rustc):
        try:
            path.relative_to(toolchain.resolve(strict=True))
        except ValueError as error:
            raise SealedBuildError("Rust compiler executable escaped the copied toolchain") from error
    closure_tools = {
        **{name: (path, False) for name, path in native_tools.items()},
        **{name: (path, False) for name, path in discovered.items()},
        "cargo": (copied_cargo, True),
        "rustc": (copied_rustc, True),
    }
    closure = {
        "schema": CLOSURE_SCHEMA,
        "native": native_closure(
            closure_tools,
            Path(args.ldd),
            environment,
            copied_roots=(toolchain.resolve(strict=True),),
        ),
        "rust_toolchain": inventory_tree(toolchain, "rust_toolchain"),
    }
    closure_bytes = canonical_bytes(closure)
    closure_sha256 = sha256_bytes(closure_bytes)
    (inputs / "build-execution-closure.json").write_bytes(closure_bytes)

    mount(str(inputs), inputs, None, MS_BIND | MS_REC, None)
    mount(None, inputs, None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, None)
    verify_read_only(inputs)

    home = workspace / "home"
    cargo_home = workspace / "cargo-home"
    target = workspace / "target"
    for path in (home, cargo_home, target):
        path.mkdir(mode=0o700)
    build_environment = {
        "AR": str(native_tools["ar"]),
        "CC": str(native_tools["cc"]),
        "CXX": str(native_tools["cxx"]),
        "CARGO_HOME": str(cargo_home),
        "CARGO_TARGET_DIR": str(target),
        "EUF_VIPER_BUILD_CONTEXT": "sealed-linux-production-evidence-v4",
        "EUF_VIPER_BUILD_EXECUTION_CLOSURE_SHA256": closure_sha256,
        "EUF_VIPER_SEALED_GIT_REVISION": args.revision,
        "EUF_VIPER_SEALED_SOURCE_MANIFEST_SHA256": args.source_manifest_sha256,
        "EUF_VIPER_SEALED_SOURCE_TREE": args.tree,
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": f"{toolchain / 'bin'}:/usr/bin:/bin",
        "RANLIB": str(native_tools["ranlib"]),
        "RUSTC": str(copied_rustc),
        "TMPDIR": str(workspace / "tmp"),
        "TZ": "UTC",
    }
    Path(build_environment["TMPDIR"]).mkdir(mode=0o700)
    completed = subprocess.run(
        [
            str(copied_cargo),
            "build",
            "--locked",
            "--offline",
            "--release",
            "--features",
            args.features,
        ],
        cwd=source,
        env=build_environment,
        capture_output=True,
        check=False,
    )
    require_success(completed, "sealed cargo build")

    binary_paths = {
        "euf-viper": target / "release" / "euf-viper",
        "euf-viper-build-features": target / "release" / "euf-viper-build-features",
    }
    artifacts: dict[str, dict[str, Any]] = {}
    output_fd = args.output_fd
    for name, path in binary_paths.items():
        content, metadata = stable_read(path, f"built artifact {name}")
        if not os.access(path, os.X_OK):
            raise SealedBuildError(f"built artifact is not executable: {path}")
        artifacts[name] = publish_bytes(output_fd, name, content, 0o500)

    payload = {
        "schema": SCHEMA,
        "status": "built",
        "artifacts": artifacts,
        "build_execution_closure": closure,
        "build_execution_closure_sha256": closure_sha256,
        "revision": args.revision,
        "source_snapshot": source_manifest,
        "source_snapshot_manifest_sha256": args.source_manifest_sha256,
        "source_tree": args.tree,
        "toolchain": args.toolchain,
    }
    publish_bytes(output_fd, "sealed-build-manifest.json", canonical_bytes(payload), 0o400)
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
            "euf-viper",
            "euf-viper-build-features",
            "sealed-build-manifest.json",
        }
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
        verified_files: dict[str, tuple[bytes, tuple[int, ...]]] = {
            "sealed-build-manifest.json": (
                manifest_raw,
                fingerprint(manifest_metadata),
            )
        }
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
        return {
            "artifacts": manifest["artifacts"],
            "manifest": str(artifact_dir / "sealed-build-manifest.json"),
            "manifest_sha256": sha256_bytes(manifest_raw),
            "source_snapshot_manifest_sha256": source_manifest_sha256,
            "status": "built",
        }
    finally:
        os.close(rebound_directory)


def outer_build(args: argparse.Namespace) -> int:
    require_linux()
    repository = args.repository.resolve(strict=True)
    artifact_dir = args.artifact_dir.absolute()
    artifact_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    artifact_dir = require_private_directory(artifact_dir, "artifact directory")
    if any(artifact_dir.iterdir()):
        raise SealedBuildError("sealed build requires an empty artifact directory")

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

        output_fd = os.open(artifact_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        script_fd = os.open(Path(__file__).resolve(), os.O_RDONLY | os.O_NOFOLLOW)
        python_path = checked_executable(Path(sys.executable), "Python")
        python_fd = os.open(python_path, os.O_RDONLY | os.O_NOFOLLOW)
        unshare_fd = os.open(tools["unshare"], os.O_RDONLY | os.O_NOFOLLOW)
        workspace = staging_parent / f"namespace-{os.getpid()}"
        try:
            native = {name: str(tools[name]) for name in ("cc", "cxx", "ar", "ranlib")}
            set_nondumpable()
            command = [
                f"/proc/self/fd/{unshare_fd}",
                "--user",
                "--map-root-user",
                "--mount",
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
                "--native-tools",
                json.dumps(native, sort_keys=True, separators=(",", ":")),
                "--revision",
                args.revision,
                "--tree",
                tree,
                "--source-manifest-sha256",
                source_manifest_sha256,
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
            )
            require_success(completed, "sealed Linux namespace build")
            summary = verify_published_build(
                output_fd,
                artifact_dir,
                revision=args.revision,
                tree=tree,
                source_manifest_sha256=source_manifest_sha256,
                toolchain=toolchain,
            )
        finally:
            for descriptor in (bundle_fd, output_fd, script_fd, python_fd, unshare_fd):
                os.close(descriptor)
            if workspace.exists():
                workspace.rmdir()

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
    script = Path(__file__).resolve(strict=True)
    unshare_fd = os.open(unshare, os.O_RDONLY | os.O_NOFOLLOW)
    python_fd = os.open(python_path, os.O_RDONLY | os.O_NOFOLLOW)
    script_fd = os.open(script, os.O_RDONLY | os.O_NOFOLLOW)
    workspace = staging / f"probe-namespace-{os.getpid()}"
    try:
        set_nondumpable()
        completed = subprocess.run(
            [
                f"/proc/self/fd/{unshare_fd}",
                "--user",
                "--map-root-user",
                "--mount",
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
    build.add_argument(
        "--features", default="certificates,production-evidence"
    )
    inside = subparsers.add_parser("_inside")
    inside.add_argument("--bundle-fd", type=int, required=True)
    inside.add_argument("--output-fd", type=int, required=True)
    inside.add_argument("--workspace", required=True)
    inside.add_argument("--sysroot", required=True)
    inside.add_argument("--ldd", required=True)
    inside.add_argument("--native-tools", required=True)
    inside.add_argument("--revision", required=True)
    inside.add_argument("--tree", required=True)
    inside.add_argument("--source-manifest-sha256", required=True)
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
