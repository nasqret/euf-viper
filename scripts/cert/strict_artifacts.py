#!/usr/bin/env python3
"""Strict JSON and no-symlink artifact I/O for promotional evidence."""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Any, Callable


class StrictArtifactError(ValueError):
    """Raised when bytes, JSON, or a path traversal is ambiguous."""


def _reject_constant(value: str) -> Any:
    raise StrictArtifactError(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictArtifactError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def strict_json_loads(text: str, context: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, StrictArtifactError) as error:
        raise StrictArtifactError(f"{context}: invalid JSON: {error}") from error


def canonical_json_bytes(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise StrictArtifactError(f"value is not canonical JSON: {error}") from error
    return (rendered + "\n").encode("utf-8")


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise StrictArtifactError(
            "O_NOFOLLOW and O_DIRECTORY are required for promotional evidence"
        )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _absolute(path: Path) -> Path:
    absolute = Path(os.path.abspath(path.expanduser()))
    if sys.platform == "darwin" and absolute.parts[:2] in {("/", "tmp"), ("/", "var")}:
        absolute = Path("/private", *absolute.parts[1:])
    return absolute


def canonical_nofollow_path(path: Path) -> Path:
    """Return the lexical absolute path used by no-follow descriptor traversal."""

    return _absolute(path)


def _open_directory_chain(
    path: Path, context: str, *, create: bool
) -> tuple[int, tuple[tuple[int, int], ...]]:
    absolute = _absolute(path)
    if not absolute.is_absolute():
        raise StrictArtifactError(f"{context}: path is not absolute")
    flags = _directory_flags()
    descriptors: list[int] = []
    try:
        current = os.open(os.sep, flags)
        descriptors.append(current)
        fingerprints = []
        root_stat = os.fstat(current)
        fingerprints.append((root_stat.st_dev, root_stat.st_ino))
        for component in absolute.parts[1:]:
            if component in {"", ".", ".."}:
                raise StrictArtifactError(
                    f"{context}: invalid path component {component!r}"
                )
            try:
                child = os.open(component, flags, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, mode=0o700, dir_fd=current)
                child = os.open(component, flags, dir_fd=current)
            descriptors.append(child)
            current = child
            metadata = os.fstat(current)
            if not stat.S_ISDIR(metadata.st_mode):
                raise StrictArtifactError(
                    f"{context}: path component is not a directory: {component}"
                )
            fingerprints.append((metadata.st_dev, metadata.st_ino))
        result_fd = os.dup(current)
        if hasattr(os, "set_inheritable"):
            os.set_inheritable(result_fd, False)
        return result_fd, tuple(fingerprints)
    except OSError as error:
        raise StrictArtifactError(
            f"{context}: cannot traverse {absolute} without symlinks: {error}"
        ) from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def ensure_directory_nofollow(path: Path, context: str) -> Path:
    absolute = _absolute(path)
    descriptor, _ = _open_directory_chain(absolute, context, create=True)
    os.close(descriptor)
    return absolute


def ensure_parent_directory_nofollow(path: Path, context: str) -> Path:
    absolute = _absolute(path)
    ensure_directory_nofollow(absolute.parent, f"{context} parent")
    return absolute


def fsync_parent_nofollow(path: Path, context: str) -> None:
    absolute = _absolute(path)
    descriptor, _ = _open_directory_chain(
        absolute.parent, f"{context} parent", create=False
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def open_append_nofollow(path: Path, context: str) -> tuple[Path, int]:
    """Open one regular append file beneath a stable no-symlink parent chain."""

    absolute = ensure_parent_directory_nofollow(path, context)
    parent_fd, fingerprints = _open_directory_chain(
        absolute.parent, f"{context} parent", create=False
    )
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = -1
    try:
        descriptor = os.open(absolute.name, flags, 0o600, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise StrictArtifactError(f"{context}: artifact is not a regular file")
        os.fsync(parent_fd)
        post_fd, post_fingerprints = _open_directory_chain(
            absolute.parent, f"{context} parent recheck", create=False
        )
        try:
            if post_fingerprints != fingerprints:
                raise StrictArtifactError(
                    f"{context}: parent path changed while opening artifact"
                )
            path_metadata = os.stat(
                absolute.name,
                dir_fd=post_fd,
                follow_symlinks=False,
            )
        finally:
            os.close(post_fd)
        if (
            not stat.S_ISREG(path_metadata.st_mode)
            or path_metadata.st_dev != metadata.st_dev
            or path_metadata.st_ino != metadata.st_ino
        ):
            raise StrictArtifactError(f"{context}: artifact path changed while opening")
        result = descriptor
        descriptor = -1
        return absolute, result
    except OSError as error:
        raise StrictArtifactError(
            f"{context}: cannot open {absolute} without symlinks: {error}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def assert_descriptor_path_nofollow(path: Path, descriptor: int, context: str) -> None:
    """Require a lexical path to still name the regular file held by descriptor."""

    absolute = _absolute(path)
    parent_fd, _ = _open_directory_chain(
        absolute.parent, f"{context} parent", create=False
    )
    try:
        descriptor_metadata = os.fstat(descriptor)
        path_metadata = os.stat(
            absolute.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(descriptor_metadata.st_mode)
            or not stat.S_ISREG(path_metadata.st_mode)
            or path_metadata.st_dev != descriptor_metadata.st_dev
            or path_metadata.st_ino != descriptor_metadata.st_ino
        ):
            raise StrictArtifactError(f"{context}: artifact path no longer names descriptor")
    except OSError as error:
        raise StrictArtifactError(
            f"{context}: cannot recheck {absolute} without symlinks: {error}"
        ) from error
    finally:
        os.close(parent_fd)


def atomic_write_nofollow(
    path: Path,
    content: bytes,
    context: str,
    *,
    immutable: bool,
    pre_publish: Callable[[], None] | None = None,
) -> Path:
    absolute = ensure_parent_directory_nofollow(path, context)
    parent_fd, fingerprints = _open_directory_chain(
        absolute.parent, f"{context} parent", create=False
    )
    temporary_name = f".{absolute.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = -1
    published = False
    try:
        if immutable:
            try:
                existing = os.stat(
                    absolute.name, dir_fd=parent_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if not stat.S_ISREG(existing.st_mode):
                    raise StrictArtifactError(
                        f"{context}: existing artifact is not a regular file"
                    )
                _, existing_bytes = read_regular_nofollow(absolute, context)
                if existing_bytes != content:
                    raise StrictArtifactError(f"{context}: immutable artifact drift")
                return absolute

        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise StrictArtifactError(f"{context}: short temporary write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1

        post_fd, post_fingerprints = _open_directory_chain(
            absolute.parent, f"{context} parent recheck", create=False
        )
        os.close(post_fd)
        if post_fingerprints != fingerprints:
            raise StrictArtifactError(f"{context}: parent path changed before publish")
        if pre_publish is not None:
            pre_publish()
        if immutable:
            os.link(
                temporary_name,
                absolute.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        else:
            os.replace(
                temporary_name,
                absolute.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        published = True
        os.fsync(parent_fd)
        post_fd, post_fingerprints = _open_directory_chain(
            absolute.parent, f"{context} published parent recheck", create=False
        )
        os.close(post_fd)
        if post_fingerprints != fingerprints:
            raise StrictArtifactError(f"{context}: parent path changed during publish")
        return absolute
    except OSError as error:
        raise StrictArtifactError(f"{context}: atomic publish failed: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not published or immutable:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def read_regular_nofollow(
    path: Path,
    context: str,
    *,
    beneath: Path | None = None,
) -> tuple[Path, bytes]:
    absolute = _absolute(path)
    if beneath is not None:
        root = _absolute(beneath)
        try:
            absolute.relative_to(root)
        except ValueError as error:
            raise StrictArtifactError(
                f"{context}: path escapes the permitted root {root}"
            ) from error
    if not absolute.name:
        raise StrictArtifactError(f"{context}: path has no file name")

    parent_fd, parent_fingerprints = _open_directory_chain(
        absolute.parent, f"{context} parent", create=False
    )
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = -1
    try:
        descriptor = os.open(absolute.name, flags, dir_fd=parent_fd)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise StrictArtifactError(f"{context}: artifact is not a regular file")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        content = b"".join(chunks)
        before_fingerprint = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_fingerprint = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_fingerprint != after_fingerprint or len(content) != after.st_size:
            raise StrictArtifactError(f"{context}: artifact changed while it was read")

        post_parent_fd, post_fingerprints = _open_directory_chain(
            absolute.parent, f"{context} parent recheck", create=False
        )
        try:
            if post_fingerprints != parent_fingerprints:
                raise StrictArtifactError(
                    f"{context}: parent path was replaced while it was read"
                )
            path_after = os.stat(
                absolute.name,
                dir_fd=post_parent_fd,
                follow_symlinks=False,
            )
        finally:
            os.close(post_parent_fd)
        if (
            not stat.S_ISREG(path_after.st_mode)
            or path_after.st_dev != after.st_dev
            or path_after.st_ino != after.st_ino
        ):
            raise StrictArtifactError(
                f"{context}: artifact path was replaced while it was read"
            )
        return absolute, content
    except OSError as error:
        raise StrictArtifactError(
            f"{context}: cannot open {absolute} without symlinks: {error}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)
