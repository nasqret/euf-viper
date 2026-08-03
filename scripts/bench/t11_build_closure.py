#!/usr/bin/env python3
"""Create and verify deterministic, immutable T11 build-closure archives.

The archive format is a deliberately small USTAR profile.  It contains one
canonical JSON manifest followed by a byte-sorted inventory rooted at
``payload/``.  No general-purpose tar extraction API is used: verification
checks every raw header and extraction creates every object relative to open
directory descriptors.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import stat
import sys
from typing import Any, BinaryIO, Iterable, Mapping, Sequence


SCHEMA = "euf-viper.t11-build-closure.v1"
MANIFEST_NAME = "manifest.json"
PAYLOAD_ROOT = "payload"
BLOCK_SIZE = 512
COPY_CHUNK_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024 * 1024
MAX_ENTRIES = 2_000_000

REQUIRED_ROOT_KINDS: Mapping[str, str] = {
    "cargo-executable": "file",
    "cargo-home": "directory",
    "native-archiver": "file",
    "native-compiler": "file",
    "native-libs": "directory",
    "native-linker": "file",
    "native-loader": "file",
    "python-runtime": "directory",
    "rust-sysroot": "directory",
    "rustc-executable": "file",
    "source-tree": "directory",
}

TOOL_ROOT_LABELS: Mapping[str, str] = {
    "cargo": "cargo-executable",
    "native-archiver": "native-archiver",
    "native-compiler": "native-compiler",
    "native-linker": "native-linker",
    "native-loader": "native-loader",
    "rustc": "rustc-executable",
}

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
LABEL_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
PROC_FD_RE = re.compile(r"/proc/self/fd/([1-9][0-9]*)\Z")

_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class ClosureError(RuntimeError):
    """A fail-closed build-closure creation or verification error."""


@dataclasses.dataclass(frozen=True)
class _Identity:
    device: int
    inode: int
    file_type: int
    permissions: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclasses.dataclass(frozen=True)
class _Entry:
    path: str
    kind: str
    mode: int
    size: int = 0
    sha256: str | None = None
    source_label: str | None = None
    source_parts: tuple[str, ...] = ()
    identity: _Identity | None = None


@dataclasses.dataclass(frozen=True)
class _Root:
    label: str
    path: str
    kind: str
    identity: _Identity


@dataclasses.dataclass(frozen=True)
class VerificationReport:
    archive_sha256: str
    manifest_sha256: str
    source_revision: str
    entries: int


def _fail(message: str) -> None:
    raise ClosureError(message)


def _identity(value: os.stat_result) -> _Identity:
    return _Identity(
        device=value.st_dev,
        inode=value.st_ino,
        file_type=stat.S_IFMT(value.st_mode),
        permissions=stat.S_IMODE(value.st_mode),
        links=value.st_nlink,
        size=value.st_size,
        mtime_ns=value.st_mtime_ns,
        ctime_ns=value.st_ctime_ns,
    )


def _path_key(value: str) -> bytes:
    try:
        return value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        _fail(f"path is not valid UTF-8: {value!r}: {error}")


def _validate_component(value: str, context: str) -> None:
    if not value or value in {".", ".."}:
        _fail(f"{context} contains a forbidden path component: {value!r}")
    if "/" in value or "\\" in value or "\x00" in value:
        _fail(f"{context} contains an invalid path component: {value!r}")
    _path_key(value)


def _validate_archive_path(value: str, context: str = "archive path") -> None:
    if not value or value.startswith("/") or value.endswith("/"):
        _fail(f"{context} is not canonical: {value!r}")
    parts = value.split("/")
    for component in parts:
        _validate_component(component, context)
    if "/".join(parts) != value:
        _fail(f"{context} is not canonical: {value!r}")
    _split_ustar_path(value)


def _split_ustar_path(value: str) -> tuple[bytes, bytes]:
    encoded = _path_key(value)
    if len(encoded) <= 100:
        return encoded, b""
    slash_positions = [index for index, byte in enumerate(encoded) if byte == 0x2F]
    for position in reversed(slash_positions):
        prefix = encoded[:position]
        name = encoded[position + 1 :]
        if prefix and len(prefix) <= 155 and name and len(name) <= 100:
            return name, prefix
    _fail(f"archive path cannot be represented canonically in USTAR: {value!r}")


def _normalized_mode(value: os.stat_result, kind: str) -> int:
    if kind == "directory":
        return 0o555
    return 0o555 if value.st_mode & 0o111 else 0o444


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            _fail("short write while creating closure artifact")
        view = view[written:]


def _read_exact(stream: BinaryIO, size: int, context: str) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            _fail(f"unexpected end of archive while reading {context}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _hash_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, COPY_CHUNK_BYTES)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _hash_stable_file(fd: int, expected: _Identity, context: str) -> str:
    before = _identity(os.fstat(fd))
    if before != expected:
        _fail(f"{context} identity changed before it was read")
    digest = _hash_fd(fd)
    after = _identity(os.fstat(fd))
    if after != before:
        _fail(f"{context} changed while it was read")
    return digest


def _open_flags(*, directory: bool) -> int:
    flags = os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW
    if directory:
        flags |= _O_DIRECTORY
    else:
        # A file-labelled root may itself be hostile.  O_NONBLOCK prevents a
        # FIFO from hanging before fstat can reject it; it is inert on files.
        flags |= _O_NONBLOCK
    return flags


def _assert_regular(value: os.stat_result, context: str) -> None:
    if not stat.S_ISREG(value.st_mode):
        _fail(f"{context} must be a regular file")
    if value.st_nlink != 1:
        _fail(f"{context} must have exactly one physical link")


def _register_physical_inode(
    seen: dict[tuple[int, int], str], value: os.stat_result, archive_path: str
) -> None:
    key = (value.st_dev, value.st_ino)
    previous = seen.get(key)
    if previous is not None:
        _fail(
            "duplicate physical inode (hard link or overlapping root): "
            f"{previous!r} and {archive_path!r}"
        )
    seen[key] = archive_path


def _scan_directory(
    fd: int,
    *,
    label: str,
    source_parts: tuple[str, ...],
    archive_base: str,
    entries: list[_Entry],
    seen_inodes: dict[tuple[int, int], str],
) -> None:
    initial = _identity(os.fstat(fd))
    try:
        names = os.listdir(fd)
    except OSError as error:
        _fail(f"cannot list source directory {archive_base!r}: {error}")
    names.sort(key=_path_key)

    for name in names:
        _validate_component(name, f"source tree {archive_base!r}")
        child_archive = f"{archive_base}/{name}"
        _validate_archive_path(child_archive)
        try:
            observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except OSError as error:
            _fail(f"cannot stat source entry {child_archive!r}: {error}")

        if stat.S_ISLNK(observed.st_mode):
            _fail(f"symlink is forbidden in closure input: {child_archive!r}")
        if stat.S_ISDIR(observed.st_mode):
            try:
                child_fd = os.open(name, _open_flags(directory=True), dir_fd=fd)
            except OSError as error:
                _fail(f"cannot open source directory {child_archive!r}: {error}")
            try:
                opened = os.fstat(child_fd)
                if _identity(opened) != _identity(observed):
                    _fail(f"source directory changed while opening: {child_archive!r}")
                _register_physical_inode(seen_inodes, opened, child_archive)
                child_parts = (*source_parts, name)
                entries.append(
                    _Entry(
                        path=child_archive,
                        kind="directory",
                        mode=0o555,
                        source_label=label,
                        source_parts=child_parts,
                        identity=_identity(opened),
                    )
                )
                _scan_directory(
                    child_fd,
                    label=label,
                    source_parts=child_parts,
                    archive_base=child_archive,
                    entries=entries,
                    seen_inodes=seen_inodes,
                )
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(observed.st_mode):
            _assert_regular(observed, f"closure input {child_archive!r}")
            try:
                child_fd = os.open(name, _open_flags(directory=False), dir_fd=fd)
            except OSError as error:
                _fail(f"cannot open source file {child_archive!r}: {error}")
            try:
                opened = os.fstat(child_fd)
                opened_identity = _identity(opened)
                if opened_identity != _identity(observed):
                    _fail(f"source file changed while opening: {child_archive!r}")
                _register_physical_inode(seen_inodes, opened, child_archive)
                digest = _hash_stable_file(
                    child_fd, opened_identity, f"closure input {child_archive!r}"
                )
                entries.append(
                    _Entry(
                        path=child_archive,
                        kind="file",
                        mode=_normalized_mode(opened, "file"),
                        size=opened.st_size,
                        sha256=digest,
                        source_label=label,
                        source_parts=(*source_parts, name),
                        identity=opened_identity,
                    )
                )
            finally:
                os.close(child_fd)
        else:
            _fail(
                "only regular files and directories are permitted; "
                f"rejected {child_archive!r}"
            )

    if _identity(os.fstat(fd)) != initial:
        _fail(f"source directory changed while scanning: {archive_base!r}")


def _scan_inputs(input_paths: Mapping[str, str]) -> tuple[list[_Root], list[_Entry]]:
    expected_labels = set(REQUIRED_ROOT_KINDS)
    actual_labels = set(input_paths)
    if actual_labels != expected_labels:
        _fail(
            "closure input labels differ: "
            f"missing={sorted(expected_labels - actual_labels)}, "
            f"extra={sorted(actual_labels - expected_labels)}"
        )

    roots: list[_Root] = []
    entries: list[_Entry] = [
        _Entry(path=PAYLOAD_ROOT, kind="directory", mode=0o555)
    ]
    seen_inodes: dict[tuple[int, int], str] = {}

    for label in sorted(REQUIRED_ROOT_KINDS, key=_path_key):
        if LABEL_RE.fullmatch(label) is None:
            _fail(f"invalid required input label: {label!r}")
        raw_path = input_paths[label]
        if not raw_path or "\x00" in raw_path:
            _fail(f"input path for {label!r} is invalid")
        source_path = os.path.abspath(raw_path)
        expected_kind = REQUIRED_ROOT_KINDS[label]
        archive_path = f"{PAYLOAD_ROOT}/{label}"
        try:
            fd = os.open(
                source_path,
                _open_flags(directory=expected_kind == "directory"),
            )
        except OSError as error:
            _fail(f"cannot open {label!r} closure input {source_path!r}: {error}")
        try:
            observed = os.fstat(fd)
            if expected_kind == "directory":
                if not stat.S_ISDIR(observed.st_mode):
                    _fail(f"closure input {label!r} must be a directory")
            else:
                _assert_regular(observed, f"closure input {label!r}")
            _register_physical_inode(seen_inodes, observed, archive_path)
            root_identity = _identity(observed)
            roots.append(
                _Root(
                    label=label,
                    path=source_path,
                    kind=expected_kind,
                    identity=root_identity,
                )
            )
            if expected_kind == "directory":
                entries.append(
                    _Entry(
                        path=archive_path,
                        kind="directory",
                        mode=0o555,
                        source_label=label,
                        identity=root_identity,
                    )
                )
                _scan_directory(
                    fd,
                    label=label,
                    source_parts=(),
                    archive_base=archive_path,
                    entries=entries,
                    seen_inodes=seen_inodes,
                )
            else:
                digest = _hash_stable_file(
                    fd, root_identity, f"closure input {label!r}"
                )
                entries.append(
                    _Entry(
                        path=archive_path,
                        kind="file",
                        mode=_normalized_mode(observed, "file"),
                        size=observed.st_size,
                        sha256=digest,
                        source_label=label,
                        identity=root_identity,
                    )
                )
        finally:
            os.close(fd)

    entries.sort(key=lambda item: _path_key(item.path))
    if len(entries) > MAX_ENTRIES:
        _fail(f"closure contains more than {MAX_ENTRIES} entries")
    paths = [item.path for item in entries]
    if len(paths) != len(set(paths)):
        _fail("closure input produces duplicate archive paths")
    return roots, entries


def _entry_record(entry: _Entry) -> dict[str, object]:
    record: dict[str, object] = {
        "kind": entry.kind,
        "mode": f"{entry.mode:04o}",
        "path": entry.path,
    }
    if entry.kind == "file":
        assert entry.sha256 is not None
        record["sha256"] = entry.sha256
        record["size"] = entry.size
    return record


def _manifest_value(
    source_revision: str, roots: Sequence[_Root], entries: Sequence[_Entry]
) -> dict[str, object]:
    return {
        "entries": [_entry_record(entry) for entry in entries],
        "roots": [
            {
                "kind": root.kind,
                "label": root.label,
                "path": f"{PAYLOAD_ROOT}/{root.label}",
            }
            for root in sorted(roots, key=lambda item: _path_key(item.label))
        ],
        "schema": SCHEMA,
        "source_revision": source_revision,
        "tools": {
            role: f"{PAYLOAD_ROOT}/{label}"
            for role, label in sorted(
                TOOL_ROOT_LABELS.items(), key=lambda item: _path_key(item[0])
            )
        },
    }


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def _octal_field(value: int, width: int, context: str) -> bytes:
    if value < 0:
        _fail(f"negative value cannot be encoded in {context}")
    digits = f"{value:0{width - 1}o}".encode("ascii")
    if len(digits) != width - 1:
        _fail(f"value is too large for canonical USTAR {context}")
    return digits + b"\0"


def _ustar_header(name: str, kind: str, mode: int, size: int) -> bytes:
    _validate_archive_path(name)
    if kind not in {"file", "directory"}:
        _fail(f"unsupported archive member kind: {kind!r}")
    if kind == "directory" and size != 0:
        _fail(f"directory member {name!r} has nonzero size")
    name_bytes, prefix_bytes = _split_ustar_path(name)
    header = bytearray(BLOCK_SIZE)
    header[0 : len(name_bytes)] = name_bytes
    header[100:108] = _octal_field(mode, 8, "mode")
    header[108:116] = _octal_field(0, 8, "uid")
    header[116:124] = _octal_field(0, 8, "gid")
    header[124:136] = _octal_field(size, 12, "size")
    header[136:148] = _octal_field(0, 12, "mtime")
    header[148:156] = b"        "
    header[156:157] = b"0" if kind == "file" else b"5"
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[345 : 345 + len(prefix_bytes)] = prefix_bytes
    checksum = sum(header)
    if checksum > 0o777777:
        _fail(f"USTAR checksum overflow for {name!r}")
    header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    return bytes(header)


def _write_padding(fd: int, size: int) -> None:
    padding = (-size) % BLOCK_SIZE
    if padding:
        _write_all(fd, b"\0" * padding)


def _write_bytes_member(fd: int, name: str, data: bytes, mode: int = 0o444) -> None:
    _write_all(fd, _ustar_header(name, "file", mode, len(data)))
    _write_all(fd, data)
    _write_padding(fd, len(data))


def _root_map(roots: Sequence[_Root]) -> dict[str, _Root]:
    return {root.label: root for root in roots}


def _entry_map(entries: Sequence[_Entry]) -> dict[str, _Entry]:
    return {entry.path: entry for entry in entries}


def _open_source_entry(
    entry: _Entry, roots: Mapping[str, _Root], entries: Mapping[str, _Entry]
) -> int:
    if entry.source_label is None or entry.identity is None:
        _fail(f"archive entry {entry.path!r} has no source identity")
    root = roots[entry.source_label]
    root_fd = os.open(root.path, _open_flags(directory=root.kind == "directory"))
    current_fd = root_fd
    try:
        if _identity(os.fstat(root_fd)) != root.identity:
            _fail(f"source root changed after inventory: {root.label!r}")
        if root.kind == "file":
            if entry.source_parts:
                _fail(f"file root {root.label!r} has an invalid relative path")
            if _identity(os.fstat(root_fd)) != entry.identity:
                _fail(f"source file changed after inventory: {entry.path!r}")
            current_fd = -1
            return root_fd

        current_archive = f"{PAYLOAD_ROOT}/{root.label}"
        for index, component in enumerate(entry.source_parts):
            current_archive = f"{current_archive}/{component}"
            expected = entries.get(current_archive)
            if expected is None or expected.identity is None:
                _fail(f"source traversal lacks inventory for {current_archive!r}")
            is_last = index == len(entry.source_parts) - 1
            want_directory = not is_last or entry.kind == "directory"
            child_fd = os.open(
                component,
                _open_flags(directory=want_directory),
                dir_fd=current_fd,
            )
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = child_fd
            if _identity(os.fstat(current_fd)) != expected.identity:
                _fail(f"source entry changed after inventory: {current_archive!r}")
        if current_fd == root_fd:
            if _identity(os.fstat(root_fd)) != entry.identity:
                _fail(f"source root changed after inventory: {entry.path!r}")
            current_fd = -1
            return root_fd
        os.close(root_fd)
        result_fd = current_fd
        current_fd = -1
        return result_fd
    except BaseException:
        if current_fd >= 0 and current_fd != root_fd:
            os.close(current_fd)
        os.close(root_fd)
        raise


def _write_source_member(
    archive_fd: int,
    entry: _Entry,
    roots: Mapping[str, _Root],
    entries: Mapping[str, _Entry],
) -> None:
    if entry.kind == "directory":
        if entry.source_label is not None:
            source_fd = _open_source_entry(entry, roots, entries)
            os.close(source_fd)
        _write_all(archive_fd, _ustar_header(entry.path, "directory", entry.mode, 0))
        return

    source_fd = _open_source_entry(entry, roots, entries)
    try:
        before = _identity(os.fstat(source_fd))
        if before != entry.identity:
            _fail(f"source file changed before archive write: {entry.path!r}")
        _write_all(
            archive_fd,
            _ustar_header(entry.path, "file", entry.mode, entry.size),
        )
        os.lseek(source_fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = entry.size
        while remaining:
            chunk = os.read(source_fd, min(COPY_CHUNK_BYTES, remaining))
            if not chunk:
                _fail(f"source file became short while archiving: {entry.path!r}")
            digest.update(chunk)
            _write_all(archive_fd, chunk)
            remaining -= len(chunk)
        if os.read(source_fd, 1):
            _fail(f"source file grew while archiving: {entry.path!r}")
        if digest.hexdigest() != entry.sha256:
            _fail(f"source file digest changed while archiving: {entry.path!r}")
        if _identity(os.fstat(source_fd)) != before:
            _fail(f"source file changed while archiving: {entry.path!r}")
        _write_padding(archive_fd, entry.size)
    finally:
        os.close(source_fd)


def _open_parent_directory(path: str) -> tuple[int, str, str]:
    absolute = os.path.abspath(path)
    parent = os.path.realpath(os.path.dirname(absolute))
    name = os.path.basename(absolute)
    _validate_component(name, "output path")
    try:
        parent_fd = os.open(parent, _open_flags(directory=True))
    except OSError as error:
        _fail(f"cannot open output parent directory {parent!r}: {error}")
    return parent_fd, name, os.path.join(parent, name)


def _reject_output_inside_inputs(output_path: str, roots: Sequence[_Root]) -> None:
    output_parent = os.path.realpath(os.path.dirname(os.path.abspath(output_path)))
    for root in roots:
        if root.kind != "directory":
            continue
        source = os.path.realpath(root.path)
        try:
            inside = os.path.commonpath((source, output_parent)) == source
        except ValueError:
            inside = False
        if inside:
            _fail(f"closure output must not be inside input root {root.label!r}")


def _same_inventory(
    left_roots: Sequence[_Root],
    left_entries: Sequence[_Entry],
    right_roots: Sequence[_Root],
    right_entries: Sequence[_Entry],
) -> bool:
    return left_roots == right_roots and left_entries == right_entries


def create_archive(
    output_path: str,
    input_paths: Mapping[str, str],
    source_revision: str,
) -> VerificationReport:
    """Create a new deterministic closure archive without replacing a path."""

    if REVISION_RE.fullmatch(source_revision) is None:
        _fail("source revision must be exactly 40 lowercase hexadecimal digits")
    roots, entries = _scan_inputs(input_paths)
    _reject_output_inside_inputs(output_path, roots)
    manifest = _manifest_value(source_revision, roots, entries)
    manifest_bytes = _canonical_json(manifest)
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        _fail(f"closure manifest exceeds {MAX_MANIFEST_BYTES} bytes")

    parent_fd, output_name, canonical_output = _open_parent_directory(output_path)
    archive_fd = -1
    created_identity: _Identity | None = None
    try:
        try:
            archive_fd = os.open(
                output_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | _O_CLOEXEC | _O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
        except FileExistsError:
            _fail(f"closure output already exists: {canonical_output!r}")
        except OSError as error:
            _fail(f"cannot create closure output {canonical_output!r}: {error}")
        created_identity = _identity(os.fstat(archive_fd))
        _assert_regular(os.fstat(archive_fd), "closure output")

        _write_bytes_member(archive_fd, MANIFEST_NAME, manifest_bytes)
        roots_by_label = _root_map(roots)
        entries_by_path = _entry_map(entries)
        for entry in entries:
            _write_source_member(archive_fd, entry, roots_by_label, entries_by_path)
        _write_all(archive_fd, b"\0" * (2 * BLOCK_SIZE))
        os.fsync(archive_fd)

        rescanned_roots, rescanned_entries = _scan_inputs(input_paths)
        if not _same_inventory(
            roots, entries, rescanned_roots, rescanned_entries
        ):
            _fail("closure inputs changed between inventory and archive completion")

        os.fchmod(archive_fd, 0o444)
        archive_sha256 = _hash_fd(archive_fd)
        report, _, _ = _verify_open_archive(archive_fd, archive_sha256)
        os.fsync(archive_fd)
        os.fsync(parent_fd)
        return report
    except BaseException:
        if archive_fd >= 0 and created_identity is not None:
            try:
                current = os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False)
                if _identity(current) == _identity(os.fstat(archive_fd)):
                    os.unlink(output_name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
            except OSError:
                pass
        raise
    finally:
        if archive_fd >= 0:
            os.close(archive_fd)
        os.close(parent_fd)


def _decode_terminated_field(field: bytes, context: str) -> bytes:
    try:
        end = field.index(0)
    except ValueError:
        _fail(f"{context} lacks a NUL terminator")
    if any(field[end + 1 :]):
        _fail(f"{context} has nonzero bytes after its terminator")
    return field[:end]


def _decode_octal(field: bytes, width: int, context: str) -> int:
    if len(field) != width or field[-1:] != b"\0":
        _fail(f"{context} is not a canonical NUL-terminated octal field")
    digits = field[:-1]
    if len(digits) != width - 1 or any(byte not in b"01234567" for byte in digits):
        _fail(f"{context} is not canonical octal")
    return int(digits, 8)


def _parse_header(header: bytes) -> tuple[str, str, int, int]:
    if len(header) != BLOCK_SIZE:
        _fail("truncated USTAR header")
    if header == b"\0" * BLOCK_SIZE:
        _fail("internal parser error: zero block parsed as a member")
    checksum_field = header[148:156]
    if not re.fullmatch(rb"[0-7]{6}\x00 ", checksum_field):
        _fail("USTAR checksum field is not canonical")
    checksum_buffer = bytearray(header)
    checksum_buffer[148:156] = b"        "
    if int(checksum_field[:6], 8) != sum(checksum_buffer):
        _fail("USTAR header checksum mismatch")

    name_bytes = _decode_terminated_field(header[0:100], "USTAR name")
    prefix_bytes = _decode_terminated_field(header[345:500], "USTAR prefix")
    if not name_bytes:
        _fail("USTAR member name is empty")
    encoded_path = prefix_bytes + (b"/" if prefix_bytes else b"") + name_bytes
    try:
        name = encoded_path.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        _fail(f"USTAR member name is not valid UTF-8: {error}")
    _validate_archive_path(name)

    mode = _decode_octal(header[100:108], 8, "USTAR mode")
    uid = _decode_octal(header[108:116], 8, "USTAR uid")
    gid = _decode_octal(header[116:124], 8, "USTAR gid")
    size = _decode_octal(header[124:136], 12, "USTAR size")
    mtime = _decode_octal(header[136:148], 12, "USTAR mtime")
    typeflag = header[156:157]
    if typeflag == b"0":
        kind = "file"
    elif typeflag == b"5":
        kind = "directory"
    else:
        _fail(
            "archive contains a forbidden member type "
            f"{typeflag!r} at {name!r}; links and special files are forbidden"
        )
    if uid != 0 or gid != 0 or mtime != 0:
        _fail(f"USTAR metadata is not normalized for {name!r}")
    if kind == "directory" and size != 0:
        _fail(f"directory archive member has nonzero size: {name!r}")
    canonical = _ustar_header(name, kind, mode, size)
    if header != canonical:
        _fail(f"USTAR header is not canonical for {name!r}")
    return name, kind, mode, size


def _exact_keys(value: object, expected: Iterable[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    actual = set(value)
    expected_set = set(expected)
    if actual != expected_set:
        _fail(
            f"{context} keys differ: missing={sorted(expected_set - actual)}, "
            f"extra={sorted(actual - expected_set)}"
        )
    return value


def _rejecting_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON object key in closure manifest: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    _fail(f"non-finite JSON value is forbidden in closure manifest: {value}")


def _parse_manifest(data: bytes) -> tuple[dict[str, Any], list[_Entry]]:
    if len(data) > MAX_MANIFEST_BYTES:
        _fail(f"closure manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    try:
        text = data.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=_rejecting_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        _fail(f"closure manifest is invalid JSON: {error}")
    if _canonical_json(value) != data:
        _fail("closure manifest JSON is not canonical")

    manifest = _exact_keys(
        value,
        ("entries", "roots", "schema", "source_revision", "tools"),
        "manifest",
    )
    if manifest["schema"] != SCHEMA:
        _fail(f"manifest.schema must equal {SCHEMA!r}")
    revision = manifest["source_revision"]
    if type(revision) is not str or REVISION_RE.fullmatch(revision) is None:
        _fail("manifest.source_revision is not a canonical Git revision")

    raw_roots = manifest["roots"]
    if type(raw_roots) is not list:
        _fail("manifest.roots must be an array")
    expected_labels = sorted(REQUIRED_ROOT_KINDS, key=_path_key)
    observed_labels: list[str] = []
    for index, raw_root in enumerate(raw_roots):
        root = _exact_keys(raw_root, ("kind", "label", "path"), f"manifest.roots[{index}]")
        label = root["label"]
        if type(label) is not str or LABEL_RE.fullmatch(label) is None:
            _fail(f"manifest.roots[{index}].label is invalid")
        observed_labels.append(label)
        if label not in REQUIRED_ROOT_KINDS:
            _fail(f"manifest contains unknown root label: {label!r}")
        if root["kind"] != REQUIRED_ROOT_KINDS[label]:
            _fail(f"manifest root kind differs for {label!r}")
        if root["path"] != f"{PAYLOAD_ROOT}/{label}":
            _fail(f"manifest root path differs for {label!r}")
    if observed_labels != expected_labels:
        _fail("manifest roots are missing, duplicated, or not canonically ordered")

    raw_tools = manifest["tools"]
    if type(raw_tools) is not dict:
        _fail("manifest.tools must be an object")
    expected_tools = {
        role: f"{PAYLOAD_ROOT}/{label}" for role, label in TOOL_ROOT_LABELS.items()
    }
    if raw_tools != expected_tools:
        _fail("manifest.tools does not identify the exact required executables")

    raw_entries = manifest["entries"]
    if type(raw_entries) is not list or not raw_entries:
        _fail("manifest.entries must be a nonempty array")
    if len(raw_entries) > MAX_ENTRIES:
        _fail(f"manifest contains more than {MAX_ENTRIES} entries")
    entries: list[_Entry] = []
    seen_paths: set[str] = set()
    for index, raw_entry in enumerate(raw_entries):
        if type(raw_entry) is not dict:
            _fail(f"manifest.entries[{index}] must be an object")
        kind = raw_entry.get("kind")
        if kind == "directory":
            entry = _exact_keys(
                raw_entry, ("kind", "mode", "path"), f"manifest.entries[{index}]"
            )
            if entry["mode"] != "0555":
                _fail(f"directory mode is not normalized at entry {index}")
            mode = 0o555
            size = 0
            digest = None
        elif kind == "file":
            entry = _exact_keys(
                raw_entry,
                ("kind", "mode", "path", "sha256", "size"),
                f"manifest.entries[{index}]",
            )
            if entry["mode"] not in {"0444", "0555"}:
                _fail(f"file mode is not normalized at entry {index}")
            mode = int(entry["mode"], 8)
            size = entry["size"]
            digest = entry["sha256"]
            if type(size) is not int or size < 0:
                _fail(f"manifest.entries[{index}].size must be a nonnegative integer")
            if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
                _fail(f"manifest.entries[{index}].sha256 is not canonical")
        else:
            _fail(f"manifest.entries[{index}].kind is invalid")
        path = entry["path"]
        if type(path) is not str:
            _fail(f"manifest.entries[{index}].path must be a string")
        _validate_archive_path(path, f"manifest.entries[{index}].path")
        if path == MANIFEST_NAME or not (
            path == PAYLOAD_ROOT or path.startswith(f"{PAYLOAD_ROOT}/")
        ):
            _fail(f"manifest entry lies outside {PAYLOAD_ROOT!r}: {path!r}")
        if path in seen_paths:
            _fail(f"duplicate manifest entry path: {path!r}")
        seen_paths.add(path)
        entries.append(
            _Entry(path=path, kind=kind, mode=mode, size=size, sha256=digest)
        )

    expected_order = sorted((item.path for item in entries), key=_path_key)
    if [item.path for item in entries] != expected_order:
        _fail("manifest entries are not canonically byte-sorted")
    by_path = _entry_map(entries)
    payload = by_path.get(PAYLOAD_ROOT)
    if payload is None or payload.kind != "directory":
        _fail("manifest must contain the payload root directory")
    for entry in entries:
        if entry.path == PAYLOAD_ROOT:
            continue
        parent = entry.path.rsplit("/", 1)[0]
        parent_entry = by_path.get(parent)
        if parent_entry is None or parent_entry.kind != "directory":
            _fail(f"manifest entry lacks a declared parent directory: {entry.path!r}")
    for label, expected_kind in REQUIRED_ROOT_KINDS.items():
        root_entry = by_path.get(f"{PAYLOAD_ROOT}/{label}")
        if root_entry is None or root_entry.kind != expected_kind:
            _fail(f"manifest root entry is missing or has wrong kind: {label!r}")
    return manifest, entries


def _consume_padding(stream: BinaryIO, size: int, context: str) -> None:
    padding = (-size) % BLOCK_SIZE
    if padding and any(_read_exact(stream, padding, f"{context} padding")):
        _fail(f"archive padding is nonzero after {context}")


def _read_member_bytes(stream: BinaryIO, size: int, context: str) -> bytes:
    if size > MAX_MANIFEST_BYTES:
        _fail(f"{context} exceeds {MAX_MANIFEST_BYTES} bytes")
    data = _read_exact(stream, size, context)
    _consume_padding(stream, size, context)
    return data


class _FreshExtractor:
    def __init__(self, destination: str) -> None:
        self.parent_fd, self.name, self.path = _open_parent_directory(destination)
        self.root_fd = -1
        self.directories: list[str] = []
        try:
            os.mkdir(self.name, 0o700, dir_fd=self.parent_fd)
            self.root_fd = os.open(
                self.name, _open_flags(directory=True), dir_fd=self.parent_fd
            )
        except FileExistsError:
            os.close(self.parent_fd)
            _fail(f"extraction destination already exists: {self.path!r}")
        except OSError as error:
            os.close(self.parent_fd)
            _fail(f"cannot create fresh extraction destination {self.path!r}: {error}")

    def close(self) -> None:
        if self.root_fd >= 0:
            os.close(self.root_fd)
            self.root_fd = -1
        if self.parent_fd >= 0:
            os.close(self.parent_fd)
            self.parent_fd = -1

    def _open_parent(self, path: str) -> tuple[int, str]:
        parts = path.split("/")
        current_fd = os.dup(self.root_fd)
        try:
            for component in parts[:-1]:
                child_fd = os.open(
                    component,
                    _open_flags(directory=True),
                    dir_fd=current_fd,
                )
                os.close(current_fd)
                current_fd = child_fd
            return current_fd, parts[-1]
        except BaseException:
            os.close(current_fd)
            raise

    def add_directory(self, path: str) -> None:
        parent_fd, name = self._open_parent(path)
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            _fail(f"extraction refuses to replace directory: {path!r}")
        except OSError as error:
            _fail(f"cannot create extracted directory {path!r}: {error}")
        finally:
            os.close(parent_fd)
        self.directories.append(path)

    def add_file_from_stream(
        self,
        stream: BinaryIO,
        path: str,
        size: int,
        expected_sha256: str,
        mode: int,
    ) -> None:
        parent_fd, name = self._open_parent(path)
        output_fd = -1
        try:
            output_fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_CLOEXEC | _O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            digest = hashlib.sha256()
            remaining = size
            while remaining:
                chunk = _read_exact(
                    stream, min(COPY_CHUNK_BYTES, remaining), f"member {path!r}"
                )
                digest.update(chunk)
                _write_all(output_fd, chunk)
                remaining -= len(chunk)
            if digest.hexdigest() != expected_sha256:
                _fail(f"archive member digest mismatch: {path!r}")
            os.fchmod(output_fd, mode)
            os.fsync(output_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            _fail(f"extraction refuses to replace file: {path!r}")
        finally:
            if output_fd >= 0:
                os.close(output_fd)
            os.close(parent_fd)
        _consume_padding(stream, size, f"member {path!r}")

    def add_bytes(self, path: str, data: bytes, mode: int) -> None:
        parent_fd, name = self._open_parent(path)
        output_fd = -1
        try:
            output_fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_CLOEXEC | _O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            _write_all(output_fd, data)
            os.fchmod(output_fd, mode)
            os.fsync(output_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            _fail(f"extraction refuses to replace file: {path!r}")
        finally:
            if output_fd >= 0:
                os.close(output_fd)
            os.close(parent_fd)

    def _chmod_directory(self, path: str, mode: int) -> None:
        fd = os.dup(self.root_fd)
        try:
            for component in path.split("/"):
                child_fd = os.open(
                    component,
                    _open_flags(directory=True),
                    dir_fd=fd,
                )
                os.close(fd)
                fd = child_fd
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)

    def finish(self, manifest: Mapping[str, Any], manifest_bytes: bytes) -> None:
        for path in sorted(self.directories, key=lambda item: (-item.count("/"), item)):
            self._chmod_directory(path, 0o555)
        os.fchmod(self.root_fd, 0o555)
        os.fsync(self.root_fd)
        _verify_extracted_inventory(self.root_fd, manifest, manifest_bytes)
        os.fsync(self.parent_fd)


def _stream_digest(stream: BinaryIO, size: int, context: str) -> str:
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = _read_exact(stream, min(COPY_CHUNK_BYTES, remaining), context)
        digest.update(chunk)
        remaining -= len(chunk)
    _consume_padding(stream, size, context)
    return digest.hexdigest()


def _verify_stream(
    stream: BinaryIO, extractor: _FreshExtractor | None
) -> tuple[dict[str, Any], bytes, int]:
    manifest_header = _read_exact(stream, BLOCK_SIZE, "manifest header")
    if manifest_header == b"\0" * BLOCK_SIZE:
        _fail("archive is empty")
    name, kind, mode, size = _parse_header(manifest_header)
    if (name, kind, mode) != (MANIFEST_NAME, "file", 0o444):
        _fail("the first archive member must be canonical manifest.json")
    manifest_bytes = _read_member_bytes(stream, size, "closure manifest")
    manifest, expected_entries = _parse_manifest(manifest_bytes)
    if extractor is not None:
        extractor.add_bytes(MANIFEST_NAME, manifest_bytes, 0o444)

    expected = _entry_map(expected_entries)
    seen: set[str] = {MANIFEST_NAME}
    observed_order: list[str] = []
    while True:
        header = _read_exact(stream, BLOCK_SIZE, "archive member header")
        if header == b"\0" * BLOCK_SIZE:
            second_zero = _read_exact(stream, BLOCK_SIZE, "second end-of-archive block")
            if second_zero != b"\0" * BLOCK_SIZE:
                _fail("archive has only one canonical end-of-archive block")
            if stream.read(1):
                _fail("archive contains trailing data after its two zero blocks")
            break
        member_name, member_kind, member_mode, member_size = _parse_header(header)
        if member_name in seen:
            _fail(f"duplicate archive member name: {member_name!r}")
        seen.add(member_name)
        entry = expected.get(member_name)
        if entry is None:
            _fail(f"archive contains an extra member: {member_name!r}")
        observed_order.append(member_name)
        if member_kind != entry.kind:
            _fail(f"archive member kind mismatch: {member_name!r}")
        if member_mode != entry.mode:
            _fail(f"archive member mode mismatch: {member_name!r}")
        if member_size != entry.size:
            _fail(f"archive member size mismatch: {member_name!r}")
        if entry.kind == "directory":
            if extractor is not None:
                extractor.add_directory(member_name)
        else:
            assert entry.sha256 is not None
            if extractor is None:
                digest = _stream_digest(
                    stream, member_size, f"member {member_name!r}"
                )
                if digest != entry.sha256:
                    _fail(f"archive member digest mismatch: {member_name!r}")
            else:
                extractor.add_file_from_stream(
                    stream,
                    member_name,
                    member_size,
                    entry.sha256,
                    entry.mode,
                )

    expected_order = [entry.path for entry in expected_entries]
    if observed_order != expected_order:
        missing = sorted(set(expected_order) - set(observed_order), key=_path_key)
        if missing:
            _fail(f"archive is missing manifest entries: {missing[:8]}")
        _fail("archive members are not in canonical manifest order")
    if extractor is not None:
        extractor.finish(manifest, manifest_bytes)
    return manifest, manifest_bytes, len(expected_entries)


def _verify_open_archive(
    fd: int, expected_sha256: str, extractor: _FreshExtractor | None = None
) -> tuple[VerificationReport, dict[str, Any], bytes]:
    if SHA256_RE.fullmatch(expected_sha256) is None:
        _fail("expected archive SHA-256 must be 64 lowercase hexadecimal digits")
    before_stat = os.fstat(fd)
    _assert_regular(before_stat, "closure archive")
    if stat.S_IMODE(before_stat.st_mode) & 0o222:
        _fail("closure archive must have no write permission bits")
    before = _identity(before_stat)
    first_digest = _hash_fd(fd)
    if first_digest != expected_sha256:
        _fail(
            "closure archive SHA-256 mismatch: "
            f"expected {expected_sha256}, observed {first_digest}"
        )
    if _identity(os.fstat(fd)) != before:
        _fail("closure archive changed while hashing")

    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
        manifest, manifest_bytes, entries = _verify_stream(stream, extractor)
    second_digest = _hash_fd(fd)
    if second_digest != expected_sha256 or _identity(os.fstat(fd)) != before:
        _fail("closure archive changed during verification")
    report = VerificationReport(
        archive_sha256=expected_sha256,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        source_revision=manifest["source_revision"],
        entries=entries,
    )
    return report, manifest, manifest_bytes


def _open_archive(path: str) -> int:
    absolute = os.path.abspath(path)
    proc_match = PROC_FD_RE.fullmatch(absolute)
    if proc_match is not None:
        source_fd = int(proc_match.group(1))
        if source_fd <= 2:
            _fail("closure archive descriptor must be greater than 2")
        try:
            if not os.get_inheritable(source_fd):
                _fail("closure archive descriptor must be explicitly inherited")
            source = os.fstat(source_fd)
            duplicate = os.dup(source_fd)
            try:
                os.set_inheritable(duplicate, False)
                if _identity(os.fstat(duplicate)) != _identity(source):
                    _fail(
                        "closure archive descriptor identity changed while duplicated"
                    )
                return duplicate
            except BaseException:
                os.close(duplicate)
                raise
        except OSError as error:
            _fail(f"cannot duplicate closure archive descriptor {source_fd}: {error}")
    try:
        return os.open(absolute, _open_flags(directory=False))
    except OSError as error:
        _fail(f"cannot open closure archive {absolute!r}: {error}")


def verify_archive(archive_path: str, expected_sha256: str) -> VerificationReport:
    """Verify an immutable closure archive against a caller-pinned digest."""

    fd = _open_archive(archive_path)
    try:
        report, _, _ = _verify_open_archive(fd, expected_sha256)
        return report
    finally:
        os.close(fd)


def extract_archive(
    archive_path: str, expected_sha256: str, destination: str
) -> VerificationReport:
    """Verify, extract into a fresh directory, and verify the extracted tree."""

    fd = _open_archive(archive_path)
    extractor: _FreshExtractor | None = None
    try:
        report, _, _ = _verify_open_archive(fd, expected_sha256)
        extractor = _FreshExtractor(destination)
        second_report, _, _ = _verify_open_archive(fd, expected_sha256, extractor)
        if second_report != report:
            _fail("closure verification report changed between verification passes")
        return report
    finally:
        if extractor is not None:
            extractor.close()
        os.close(fd)


def _verify_extracted_inventory(
    root_fd: int, manifest: Mapping[str, Any], manifest_bytes: bytes
) -> None:
    expected: dict[str, tuple[str, int, int, str | None]] = {
        MANIFEST_NAME: (
            "file",
            0o444,
            len(manifest_bytes),
            hashlib.sha256(manifest_bytes).hexdigest(),
        )
    }
    for raw in manifest["entries"]:
        if raw["kind"] == "directory":
            expected[raw["path"]] = ("directory", 0o555, 0, None)
        else:
            expected[raw["path"]] = (
                "file",
                int(raw["mode"], 8),
                raw["size"],
                raw["sha256"],
            )

    observed: dict[str, tuple[str, int, int, str | None]] = {}
    seen_inodes: dict[tuple[int, int], str] = {}

    def walk(directory_fd: int, prefix: str) -> None:
        names = os.listdir(directory_fd)
        names.sort(key=_path_key)
        for name in names:
            _validate_component(name, "extracted closure")
            path = f"{prefix}/{name}" if prefix else name
            value = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(value.st_mode):
                _fail(f"symlink appeared in extracted closure: {path!r}")
            _register_physical_inode(seen_inodes, value, path)
            mode = stat.S_IMODE(value.st_mode)
            if mode & 0o222:
                _fail(f"extracted closure entry remains writable: {path!r}")
            if stat.S_ISDIR(value.st_mode):
                observed[path] = ("directory", mode, 0, None)
                child_fd = os.open(
                    name, _open_flags(directory=True), dir_fd=directory_fd
                )
                try:
                    walk(child_fd, path)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(value.st_mode):
                _assert_regular(value, f"extracted closure entry {path!r}")
                child_fd = os.open(
                    name, _open_flags(directory=False), dir_fd=directory_fd
                )
                try:
                    child_identity = _identity(os.fstat(child_fd))
                    digest = _hash_stable_file(
                        child_fd, child_identity, f"extracted closure entry {path!r}"
                    )
                finally:
                    os.close(child_fd)
                observed[path] = ("file", mode, value.st_size, digest)
            else:
                _fail(f"special file appeared in extracted closure: {path!r}")

    root_mode = stat.S_IMODE(os.fstat(root_fd).st_mode)
    if root_mode != 0o555:
        _fail("extracted closure root is not mode 0555")
    walk(root_fd, "")
    if observed != expected:
        missing = sorted(set(expected) - set(observed), key=_path_key)
        extra = sorted(set(observed) - set(expected), key=_path_key)
        mismatched = sorted(
            (path for path in set(expected) & set(observed) if expected[path] != observed[path]),
            key=_path_key,
        )
        _fail(
            "extracted closure inventory mismatch: "
            f"missing={missing[:8]}, extra={extra[:8]}, mismatched={mismatched[:8]}"
        )


def _parse_input_specs(values: Sequence[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            _fail(f"closure input must use LABEL=PATH syntax: {value!r}")
        label, path = value.split("=", 1)
        if LABEL_RE.fullmatch(label) is None:
            _fail(f"closure input label is invalid: {label!r}")
        if label in result:
            _fail(f"duplicate closure input label: {label!r}")
        if not path:
            _fail(f"closure input path is empty for label {label!r}")
        result[label] = path
    return result


def _report_value(report: VerificationReport, **extra: object) -> dict[str, object]:
    value: dict[str, object] = {
        "archive_sha256": report.archive_sha256,
        "entries": report.entries,
        "manifest_sha256": report.manifest_sha256,
        "schema": SCHEMA,
        "source_revision": report.source_revision,
        "status": "verified",
    }
    value.update(extra)
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create a new closure archive")
    create.add_argument("--output", required=True)
    create.add_argument("--source-revision", required=True)
    create.add_argument(
        "--input",
        action="append",
        default=[],
        metavar="LABEL=PATH",
        help="one exact labelled root; all required labels must be supplied",
    )

    verify = subparsers.add_parser("verify", help="verify a closure archive")
    verify.add_argument("--archive", required=True)
    verify.add_argument("--sha256", required=True)

    extract = subparsers.add_parser(
        "extract", help="verify and extract into a fresh read-only directory"
    )
    extract.add_argument("--archive", required=True)
    extract.add_argument("--sha256", required=True)
    extract.add_argument("--destination", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            report = create_archive(
                args.output,
                _parse_input_specs(args.input),
                args.source_revision,
            )
            result = _report_value(report, archive=os.path.abspath(args.output))
        elif args.command == "verify":
            report = verify_archive(args.archive, args.sha256)
            result = _report_value(report, archive=os.path.abspath(args.archive))
        else:
            report = extract_archive(args.archive, args.sha256, args.destination)
            result = _report_value(
                report,
                archive=os.path.abspath(args.archive),
                destination=os.path.abspath(args.destination),
            )
    except (ClosureError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(_canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
