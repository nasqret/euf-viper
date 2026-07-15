#!/usr/bin/env python3
"""Linux-only descriptor publication primitives for the T5 campaign."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


AT_EMPTY_PATH = 0x1000
READ_CHUNK = 1024 * 1024


class PublicationError(ValueError):
    """Raised when Linux cannot prove the descriptor publication contract."""


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _validate_name(name: str, context: str) -> str:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise PublicationError(f"{context} must be one safe directory entry")
    return name


def sha256_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while chunk := os.pread(descriptor, READ_CHUNK, offset):
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def read_fd(descriptor: int, *, maximum_bytes: int | None = None) -> bytes:
    output = bytearray()
    offset = 0
    while chunk := os.pread(descriptor, READ_CHUNK, offset):
        output.extend(chunk)
        offset += len(chunk)
        if maximum_bytes is not None and len(output) > maximum_bytes:
            raise PublicationError("descriptor payload exceeds its declared bound")
    return bytes(output)


def write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise PublicationError("descriptor write made no progress")
        offset += written


def fsync_directory(descriptor: int) -> None:
    os.fsync(descriptor)


def open_unnamed_linkable_file(directory_descriptor: int) -> int:
    if not sys.platform.startswith("linux") or not hasattr(os, "O_TMPFILE"):
        raise PublicationError("T5 publication requires Linux O_TMPFILE")
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_TMPFILE
    try:
        descriptor = os.open(".", flags, 0o600, dir_fd=directory_descriptor)
    except OSError as error:
        raise PublicationError(
            f"result filesystem does not provide linkable O_TMPFILE: {error}"
        ) from error
    descriptor_stat = os.fstat(descriptor)
    if not stat.S_ISREG(descriptor_stat.st_mode) or descriptor_stat.st_nlink != 0:
        os.close(descriptor)
        raise PublicationError("O_TMPFILE descriptor is not an unnamed regular inode")
    return descriptor


def seal_unnamed_file(descriptor: int) -> tuple[str, os.stat_result]:
    try:
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
    except OSError as error:
        raise PublicationError(f"cannot seal unnamed publication inode: {error}") from error
    descriptor_stat = os.fstat(descriptor)
    if (
        not stat.S_ISREG(descriptor_stat.st_mode)
        or descriptor_stat.st_nlink != 0
        or stat.S_IMODE(descriptor_stat.st_mode) != 0o444
    ):
        raise PublicationError("sealed publication inode has invalid type, mode, or links")
    digest = sha256_fd(descriptor)
    if os.fstat(descriptor).st_size != descriptor_stat.st_size:
        raise PublicationError("sealed publication inode changed while hashing")
    return digest, descriptor_stat


def prepare_unnamed_bytes(
    directory_descriptor: int, payload: bytes
) -> tuple[int, str, os.stat_result]:
    descriptor = open_unnamed_linkable_file(directory_descriptor)
    try:
        write_all(descriptor, payload)
        digest, descriptor_stat = seal_unnamed_file(descriptor)
    except OSError as error:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise PublicationError(
            f"cannot bind read-only descriptor to just-linked inode: {error}"
        ) from error
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    return descriptor, digest, descriptor_stat


def _call_linkat(
    source_descriptor: int,
    destination_directory_descriptor: int,
    destination_name: str,
) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    linkat = libc.linkat
    linkat.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    )
    linkat.restype = ctypes.c_int
    if (
        linkat(
            source_descriptor,
            b"",
            destination_directory_descriptor,
            os.fsencode(destination_name),
            AT_EMPTY_PATH,
        )
        == 0
    ):
        return 0
    return ctypes.get_errno()


def link_unnamed_inode_no_replace(
    source_descriptor: int,
    directory_descriptor: int,
    destination_name: str,
) -> os.stat_result:
    _validate_name(destination_name, "publication name")
    before = os.fstat(source_descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 0:
        raise PublicationError("publication source must be one unnamed regular inode")
    error = _call_linkat(source_descriptor, directory_descriptor, destination_name)
    if error == errno.EEXIST:
        raise PublicationError(
            f"publication destination already exists: {destination_name}"
        )
    if error == errno.EPERM:
        raise PublicationError(
            "cannot link O_TMPFILE descriptor with AT_EMPTY_PATH: permission denied; "
            "Linux requires CAP_DAC_READ_SEARCH and this campaign forbids the "
            "/proc/self/fd pathname fallback"
        )
    if error:
        raise PublicationError(
            "cannot link O_TMPFILE descriptor with AT_EMPTY_PATH: "
            f"{os.strerror(error)}"
        )
    after = os.fstat(source_descriptor)
    if not _same_inode(before, after) or after.st_nlink != 1:
        raise PublicationError("published inode does not have exactly one link")
    return after


def open_regular_no_follow(
    directory_descriptor: int, name: str, context: str
) -> int:
    _validate_name(name, context)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError as error:
        raise PublicationError(f"cannot open {context} {name}: {error}") from error
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise PublicationError(f"{context} is not a regular file")
    return descriptor


def reopen_linked_inode_read_only(
    source_descriptor: int,
    directory_descriptor: int,
    name: str,
) -> int:
    """Acquire a read-only handle to the just-linked authoritative inode."""

    source_stat = os.fstat(source_descriptor)
    descriptor = open_regular_no_follow(
        directory_descriptor, name, "just-linked publication"
    )
    try:
        descriptor_stat = os.fstat(descriptor)
        named_stat = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if (
            not _same_inode(source_stat, descriptor_stat)
            or not _same_inode(descriptor_stat, named_stat)
            or descriptor_stat.st_nlink != 1
            or stat.S_IMODE(descriptor_stat.st_mode) != 0o444
        ):
            raise PublicationError(
                "just-linked name does not identify the sealed descriptor inode"
            )
        return descriptor
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def verify_named_file(
    *,
    directory_descriptor: int,
    name: str,
    expected_descriptor: int | None,
    expected_sha256: str,
    expected_payload: bytes | None = None,
) -> os.stat_result:
    descriptor = open_regular_no_follow(directory_descriptor, name, "published file")
    try:
        descriptor_stat = os.fstat(descriptor)
        try:
            named_stat = os.stat(
                name, dir_fd=directory_descriptor, follow_symlinks=False
            )
        except OSError as error:
            raise PublicationError(f"cannot restat published file {name}: {error}") from error
        if not _same_inode(descriptor_stat, named_stat):
            raise PublicationError("published name changed after no-follow open")
        if expected_descriptor is not None and not _same_inode(
            descriptor_stat, os.fstat(expected_descriptor)
        ):
            raise PublicationError("published name differs from authoritative descriptor")
        if descriptor_stat.st_nlink != 1:
            raise PublicationError("published inode must have exactly one link")
        if stat.S_IMODE(descriptor_stat.st_mode) != 0o444:
            raise PublicationError("published inode mode must be 0444")
        digest = sha256_fd(descriptor)
        if digest != expected_sha256:
            raise PublicationError("published inode SHA-256 mismatch")
        if expected_payload is not None and read_fd(
            descriptor, maximum_bytes=len(expected_payload)
        ) != expected_payload:
            raise PublicationError("published inode content mismatch")
        os.fsync(descriptor)
        return descriptor_stat
    except OSError as error:
        raise PublicationError(f"cannot fsync published inode: {error}") from error
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


@dataclass
class PinnedResultRoot:
    namespace_path: Path
    results_path: Path
    namespace_descriptor: int
    results_descriptor: int
    namespace_stat: os.stat_result
    results_stat: os.stat_result

    @classmethod
    def open(
        cls,
        namespace_path: Path,
        *,
        expected_namespace: tuple[int, int] | None = None,
        expected_results: tuple[int, int] | None = None,
    ) -> "PinnedResultRoot":
        namespace_path = Path(os.path.abspath(namespace_path))
        results_path = namespace_path / "results"
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            namespace_descriptor = os.open(namespace_path, flags)
        except OSError as error:
            raise PublicationError(
                f"cannot open remote namespace {namespace_path}: {error}"
            ) from error
        results_descriptor: int | None = None
        try:
            namespace_stat = os.fstat(namespace_descriptor)
            results_descriptor = os.open(
                "results", flags, dir_fd=namespace_descriptor
            )
            results_stat = os.fstat(results_descriptor)
            pinned = cls(
                namespace_path,
                results_path,
                namespace_descriptor,
                results_descriptor,
                namespace_stat,
                results_stat,
            )
            pinned.verify_paths()
            if expected_namespace is not None and expected_namespace != (
                namespace_stat.st_dev,
                namespace_stat.st_ino,
            ):
                raise PublicationError("remote namespace identity drift")
            if expected_results is not None and expected_results != (
                results_stat.st_dev,
                results_stat.st_ino,
            ):
                raise PublicationError("result-directory identity drift")
            return pinned
        except BaseException:
            if results_descriptor is not None:
                try:
                    os.close(results_descriptor)
                except OSError:
                    pass
            try:
                os.close(namespace_descriptor)
            except OSError:
                pass
            raise

    def verify_paths(self) -> None:
        current_namespace = os.stat(self.namespace_path, follow_symlinks=False)
        current_results = os.stat(self.results_path, follow_symlinks=False)
        relative_results = os.stat(
            "results", dir_fd=self.namespace_descriptor, follow_symlinks=False
        )
        if (
            not stat.S_ISDIR(current_namespace.st_mode)
            or not _same_inode(current_namespace, self.namespace_stat)
            or not _same_inode(os.fstat(self.namespace_descriptor), self.namespace_stat)
        ):
            raise PublicationError("named remote namespace no longer matches its descriptor")
        if (
            not stat.S_ISDIR(current_results.st_mode)
            or not _same_inode(current_results, self.results_stat)
            or not _same_inode(relative_results, self.results_stat)
            or not _same_inode(os.fstat(self.results_descriptor), self.results_stat)
        ):
            raise PublicationError("named result root no longer matches its descriptor")

    def identity_json(self, namespace_id: str) -> dict[str, object]:
        return {
            "id": namespace_id,
            "path": str(self.namespace_path),
            "device": self.namespace_stat.st_dev,
            "inode": self.namespace_stat.st_ino,
            "results_path": str(self.results_path),
            "results_device": self.results_stat.st_dev,
            "results_inode": self.results_stat.st_ino,
        }

    def close(self) -> None:
        for descriptor in (self.results_descriptor, self.namespace_descriptor):
            try:
                os.close(descriptor)
            except OSError:
                pass


@dataclass(frozen=True)
class PublishedFile:
    name: str
    sha256: str
    stat: os.stat_result


def publish_bytes_no_replace(
    *,
    directory_descriptor: int,
    name: str,
    payload: bytes,
    boundary_hook: Callable[[str], None] | None = None,
    hook_prefix: str = "file",
) -> PublishedFile:
    writable_descriptor, digest, _ = prepare_unnamed_bytes(
        directory_descriptor, payload
    )
    readonly_descriptor: int | None = None
    try:
        if boundary_hook is not None:
            boundary_hook(f"{hook_prefix}_ready")
        link_unnamed_inode_no_replace(
            writable_descriptor, directory_descriptor, name
        )
        readonly_descriptor = reopen_linked_inode_read_only(
            writable_descriptor, directory_descriptor, name
        )
        os.close(writable_descriptor)
        writable_descriptor = -1
        if boundary_hook is not None:
            boundary_hook(f"{hook_prefix}_linked")
        try:
            fsync_directory(directory_descriptor)
        except OSError as error:
            raise PublicationError(
                f"cannot fsync {hook_prefix} publication directory: {error}"
            ) from error
        verified = verify_named_file(
            directory_descriptor=directory_descriptor,
            name=name,
            expected_descriptor=readonly_descriptor,
            expected_sha256=digest,
            expected_payload=payload,
        )
        if boundary_hook is not None:
            boundary_hook(f"{hook_prefix}_verified")
        return PublishedFile(name, digest, verified)
    finally:
        for descriptor in (readonly_descriptor, writable_descriptor):
            if descriptor is None or descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except OSError:
                pass
