#!/usr/bin/env python3
"""Inventory and mutation-monitor the exact T1 release source snapshot."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import select
import stat
import struct
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any


IN_ATTRIB = 0x00000004
IN_MODIFY = 0x00000002
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
WATCH_MASK = (
    IN_ATTRIB
    | IN_MODIFY
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
)
EVENT_NAMES = {
    IN_ATTRIB: "ATTRIB",
    IN_MODIFY: "WRITE",
    IN_CLOSE_WRITE: "CLOSE_WRITE",
    IN_MOVED_FROM: "MOVE_FROM",
    IN_MOVED_TO: "MOVE_TO",
    IN_CREATE: "CREATE",
    IN_DELETE: "DELETE",
    IN_DELETE_SELF: "DELETE_SELF",
    IN_MOVE_SELF: "MOVE_SELF",
    IN_Q_OVERFLOW: "QUEUE_OVERFLOW",
    IN_IGNORED: "IGNORED",
}
REVISION_CHARS = frozenset("0123456789abcdef")


def die(message: str) -> None:
    raise SystemExit(message)


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("ascii")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            die(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def reject_nonfinite(value: str) -> None:
    die(f"nonfinite JSON number: {value}")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            die("short write while publishing build evidence")
        offset += written


def publish(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o400,
    )
    try:
        write_all(descriptor, content)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def require_descriptor_path(descriptor: int, path: Path, label: str) -> Path:
    if not sys.platform.startswith("linux"):
        die(f"{label} descriptor binding requires Linux procfs")
    canonical = path.resolve(strict=True)
    if canonical != path or path.is_symlink():
        die(f"{label} path must be canonical and non-symlinked")
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        die(f"{label} descriptor is not a regular file")
    target = Path(f"/proc/self/fd/{descriptor}").resolve(strict=True)
    if target != canonical:
        die(f"{label} descriptor does not name its supplied path")
    return canonical


def publish_descriptor(descriptor: int, path: Path, content: bytes, label: str) -> None:
    require_descriptor_path(descriptor, path, label)
    metadata = os.fstat(descriptor)
    if metadata.st_size != 0:
        die(f"{label} descriptor was not fresh")
    os.lseek(descriptor, 0, os.SEEK_SET)
    write_all(descriptor, content)
    os.fchmod(descriptor, 0o400)
    os.fsync(descriptor)
    if descriptor_bytes(descriptor, executable=False, label=label) != content:
        die(f"{label} descriptor changed while published")


def git(repository: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
    ).stdout


def valid_revision(value: str) -> str:
    if len(value) != 40 or any(character not in REVISION_CHARS for character in value):
        die("revision must be exactly 40 lowercase hexadecimal digits")
    return value


def git_blob_sha1(content: bytes) -> str:
    digest = hashlib.sha1()
    digest.update(f"blob {len(content)}\0".encode("ascii"))
    digest.update(content)
    return digest.hexdigest()


def expected_tree(repository: Path, revision: str) -> tuple[str, dict[str, tuple[str, str]]]:
    tree = git(repository, "rev-parse", f"{revision}^{{tree}}").decode("ascii").strip()
    raw = git(repository, "ls-tree", "-r", "-z", "--full-tree", revision)
    entries: dict[str, tuple[str, str]] = {}
    for item in raw.split(b"\0"):
        if not item:
            continue
        header, path_bytes = item.split(b"\t", 1)
        mode, object_type, blob = header.decode("ascii").split(" ")
        path = path_bytes.decode("utf-8")
        pure = PurePosixPath(path)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            die(f"unsafe Git path in source tree: {path!r}")
        if object_type != "blob" or mode not in {"100644", "100755"}:
            die(f"unsupported Git tree entry for build snapshot: {mode} {object_type} {path}")
        if path in entries:
            die(f"duplicate Git path in source tree: {path}")
        entries[path] = (mode, blob)
    return tree, entries


def actual_paths(snapshot: Path) -> set[str]:
    paths: set[str] = set()
    for root, directories, files in os.walk(snapshot, topdown=True, followlinks=False):
        root_path = Path(root)
        for name in list(directories):
            path = root_path / name
            relative = path.relative_to(snapshot).as_posix()
            if path.is_symlink():
                paths.add(relative)
                directories.remove(name)
            elif not path.is_dir():
                die(f"non-directory encountered while walking snapshot: {relative}")
            else:
                paths.add(relative)
        for name in files:
            paths.add((root_path / name).relative_to(snapshot).as_posix())
    return paths


def inventory(repository: Path, revision: str, snapshot: Path) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    snapshot = snapshot.resolve(strict=True)
    revision = valid_revision(revision)
    actual_revision = git(repository, "rev-parse", f"{revision}^{{commit}}").decode().strip()
    if actual_revision != revision:
        die("repository cannot resolve the exact build revision")
    tree, expected = expected_tree(repository, revision)
    actual = actual_paths(snapshot)
    expected_paths = set(expected)
    for relative in expected:
        expected_paths.update(
            parent.as_posix()
            for parent in PurePosixPath(relative).parents
            if parent != PurePosixPath(".")
        )
    if actual != expected_paths:
        missing = sorted(expected_paths - actual)[:8]
        extra = sorted(actual - expected_paths)[:8]
        die(f"snapshot path inventory mismatch: missing={missing}, extra={extra}")
    if any(
        path in {".cargo/config", ".cargo/config.toml"}
        or path.endswith("/.cargo/config")
        or path.endswith("/.cargo/config.toml")
        for path in actual
    ):
        die("source snapshot contains Cargo configuration")

    rows: list[dict[str, Any]] = []
    source_bytes = 0
    for relative in sorted(expected):
        mode, expected_blob = expected[relative]
        path = snapshot.joinpath(*PurePosixPath(relative).parts)
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            die(f"snapshot regular-file mode mismatch: {relative}")
        executable = bool(stat.S_IMODE(metadata.st_mode) & 0o111)
        if executable != (mode == "100755"):
            die(f"snapshot executable bit mismatch: {relative}")
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            content = b""
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                content += chunk
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                die(f"snapshot file changed while inventoried: {relative}")
        finally:
            os.close(descriptor)
        actual_blob = git_blob_sha1(content)
        if actual_blob != expected_blob:
            die(f"snapshot blob mismatch: {relative}")
        source_bytes += len(content)
        rows.append(
            {
                "blob": expected_blob,
                "bytes": len(content),
                "mode": mode,
                "path": relative,
                "sha256": sha256(content),
            }
        )
    rows_digest = sha256(b"".join(canonical_bytes(row) for row in rows))
    return {
        "schema": "euf-viper.t1-source-snapshot-inventory.v1",
        "repository": str(repository),
        "revision": revision,
        "snapshot": str(snapshot),
        "tree": tree,
        "files": len(rows),
        "source_bytes": source_bytes,
        "entries_sha256": rows_digest,
    }


def inventory_command(args: argparse.Namespace) -> None:
    payload = inventory(args.repository, args.revision, args.snapshot)
    publish(args.output, canonical_bytes(payload))


def external_tree_inventory(root: Path) -> dict[str, Any]:
    """Bind an external dependency tree without trusting path metadata alone."""
    root = root.resolve(strict=True)
    if root.is_symlink() or not root.is_dir():
        die(f"external inventory root is not a canonical directory: {root}")
    rows: list[dict[str, Any]] = []
    file_count = 0
    directory_count = 1
    total_bytes = 0
    for current, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False
    ):
        current_path = Path(current)
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            try:
                relative.encode("utf-8")
            except UnicodeEncodeError:
                die(f"external dependency path is not UTF-8: {relative!r}")
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                die(f"external dependency directory is not plain: {relative}")
            directory_count += 1
            rows.append(
                {
                    "kind": "directory",
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    "path": relative,
                }
            )
        for name in file_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            try:
                relative.encode("utf-8")
            except UnicodeEncodeError:
                die(f"external dependency path is not UTF-8: {relative!r}")
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                die(f"external dependency file is not regular: {relative}")
            content = path.read_bytes()
            after = path.stat()
            if (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_size,
                metadata.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_size,
                after.st_mtime_ns,
            ):
                die(f"external dependency file changed while inventoried: {relative}")
            file_count += 1
            total_bytes += len(content)
            rows.append(
                {
                    "bytes": len(content),
                    "kind": "file",
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    "path": relative,
                    "sha256": sha256(content),
                }
            )
    rows.sort(key=lambda row: (row["path"], row["kind"]))
    return {
        "schema": "euf-viper.t1-external-dependency-inventory.v1",
        "root": str(root),
        "directories": directory_count,
        "files": file_count,
        "bytes": total_bytes,
        "entries_sha256": sha256(b"".join(canonical_bytes(row) for row in rows)),
    }


def external_tree_inventory_command(args: argparse.Namespace) -> None:
    publish(args.output, canonical_bytes(external_tree_inventory(args.root)))


def all_directories(snapshot: Path) -> list[Path]:
    directories = [snapshot]
    for root, names, _ in os.walk(snapshot, topdown=True, followlinks=False):
        root_path = Path(root)
        for name in list(names):
            path = root_path / name
            if path.is_symlink():
                names.remove(name)
            else:
                directories.append(path)
    return sorted(set(directories))


def event_labels(mask: int) -> list[str]:
    return [name for bit, name in EVENT_NAMES.items() if mask & bit]


def monitor_command(args: argparse.Namespace) -> None:
    if not sys.platform.startswith("linux"):
        die("recursive mutation monitoring requires Linux inotify")
    snapshot = args.snapshot.resolve(strict=True)
    libc = ctypes.CDLL(None, use_errno=True)
    inotify_init1 = libc.inotify_init1
    inotify_init1.argtypes = [ctypes.c_int]
    inotify_init1.restype = ctypes.c_int
    inotify_add_watch = libc.inotify_add_watch
    inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    inotify_add_watch.restype = ctypes.c_int
    inotify_descriptor = inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
    if inotify_descriptor < 0:
        error = ctypes.get_errno()
        die(f"inotify_init1 failed: {os.strerror(error)}")
    control_descriptor = args.control_fd
    try:
        control_metadata = os.fstat(control_descriptor)
    except OSError as error:
        die(f"cannot inspect monitor control descriptor: {error}")
    if not (
        stat.S_ISFIFO(control_metadata.st_mode) or stat.S_ISSOCK(control_metadata.st_mode)
    ):
        die("monitor control descriptor must be an anonymous pipe or socket")
    os.set_blocking(control_descriptor, False)
    watches: dict[int, Path] = {}
    try:
        for directory in all_directories(snapshot):
            watch = inotify_add_watch(
                inotify_descriptor, os.fsencode(directory), WATCH_MASK
            )
            if watch < 0:
                error = ctypes.get_errno()
                die(f"inotify_add_watch failed for {directory}: {os.strerror(error)}")
            watches[watch] = directory
        require_descriptor_path(args.ready_fd, args.ready, "monitor ready output")
        require_descriptor_path(args.events_fd, args.events, "monitor event output")
        require_descriptor_path(args.receipt_fd, args.receipt, "monitor receipt output")
        events_descriptor = args.events_fd
        if os.fstat(events_descriptor).st_size != 0:
            die("monitor event descriptor was not fresh")
        os.lseek(events_descriptor, 0, os.SEEK_SET)
        events_digest = hashlib.sha256()
        event_count = 0
        poll_cycles = 0
        ready = {
            "schema": "euf-viper.t1-mutation-monitor-ready.v2",
            "control": "parent-owned-pipe-eof.v1",
            "monitor_pid": os.getpid(),
            "parent_pid": os.getppid(),
            "snapshot": str(snapshot),
            "watched_directories": len(watches),
            "watch_mask": WATCH_MASK,
        }
        publish_descriptor(
            args.ready_fd, args.ready, canonical_bytes(ready), "monitor ready output"
        )
        poller = select.poll()
        poller.register(inotify_descriptor, select.POLLIN | select.POLLERR)
        poller.register(
            control_descriptor,
            select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
        )

        def consume_events(data: bytes) -> None:
            nonlocal event_count
            offset = 0
            while offset < len(data):
                if len(data) - offset < 16:
                    die("inotify returned a truncated event header")
                watch, mask, cookie, length = struct.unpack_from("iIII", data, offset)
                offset += 16
                if length > len(data) - offset:
                    die("inotify returned a truncated event name")
                raw_name = data[offset : offset + length].split(b"\0", 1)[0]
                offset += length
                directory = watches.get(watch)
                name = os.fsdecode(raw_name) if raw_name else ""
                path = directory / name if directory is not None and name else directory
                event = {
                    "cookie": cookie,
                    "events": event_labels(mask),
                    "mask": mask,
                    "path": None
                    if path is None
                    else path.relative_to(snapshot).as_posix()
                    if path != snapshot
                    else ".",
                }
                rendered = canonical_bytes(event)
                write_all(events_descriptor, rendered)
                events_digest.update(rendered)
                event_count += 1

        try:
            shutdown = False
            while not shutdown:
                poll_cycles += 1
                for ready_descriptor, mask in poller.poll(50):
                    if ready_descriptor == inotify_descriptor:
                        if mask & select.POLLERR:
                            die("inotify monitor descriptor reported an error")
                        consume_events(os.read(inotify_descriptor, 1024 * 1024))
                        continue
                    if mask & (select.POLLERR | select.POLLNVAL):
                        die("monitor control descriptor failed")
                    control = os.read(control_descriptor, 4096)
                    if control:
                        die("monitor control protocol accepts EOF only")
                    shutdown = True
            while True:
                ready_events = poller.poll(25)
                if not ready_events:
                    break
                consumed = False
                for ready_descriptor, mask in ready_events:
                    if ready_descriptor != inotify_descriptor:
                        continue
                    if mask & select.POLLERR:
                        die("inotify monitor descriptor reported an error while draining")
                    data = os.read(inotify_descriptor, 1024 * 1024)
                    if data:
                        consume_events(data)
                        consumed = True
                if not consumed:
                    break
            os.fchmod(events_descriptor, 0o400)
            os.fsync(events_descriptor)
        finally:
            pass
        receipt = {
            "schema": "euf-viper.t1-mutation-monitor-receipt.v2",
            "control": "parent-owned-pipe-eof.v1",
            "monitor_pid": os.getpid(),
            "parent_pid": os.getppid(),
            "poll_cycles": poll_cycles,
            "snapshot": str(snapshot),
            "watched_directories": len(watches),
            "watch_mask": WATCH_MASK,
            "event_count": event_count,
            "events": {
                "path": str(args.events),
                "sha256": events_digest.hexdigest(),
                "bytes": os.fstat(events_descriptor).st_size,
            },
            "status": "clean" if event_count == 0 else "mutated",
        }
        publish_descriptor(
            args.receipt_fd,
            args.receipt,
            canonical_bytes(receipt),
            "monitor receipt output",
        )
        if event_count:
            raise SystemExit(3)
    finally:
        os.close(inotify_descriptor)


def load_canonical(path: Path) -> dict[str, Any]:
    content = path.read_bytes()
    value = json.loads(
        content,
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_nonfinite,
        parse_float=lambda value: die(f"floating point JSON is forbidden: {value}"),
    )
    if not isinstance(value, dict) or canonical_bytes(value) != content:
        die(f"artifact is not a canonical JSON object: {path}")
    return value


def load_canonical_descriptor(
    descriptor: int, path: Path, label: str
) -> tuple[dict[str, Any], bytes]:
    canonical = require_descriptor_path(descriptor, path, label)
    if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o400:
        die(f"{label} descriptor is not sealed mode 0400")
    content = descriptor_bytes(descriptor, executable=False, label=label)
    value = json.loads(
        content,
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_nonfinite,
        parse_float=lambda item: die(f"floating point JSON is forbidden: {item}"),
    )
    if not isinstance(value, dict) or canonical_bytes(value) != content:
        die(f"{label} descriptor is not a canonical JSON object: {canonical}")
    return value, content


def descriptor_bytes(descriptor: int, *, executable: bool, label: str) -> bytes:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        die(f"{label} descriptor is not a regular file")
    if executable and before.st_mode & 0o111 == 0:
        die(f"{label} descriptor is not executable")
    content = bytearray()
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        if not chunk:
            die(f"{label} descriptor became short while read")
        content.extend(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, before.st_size):
        die(f"{label} descriptor grew while read")
    after = os.fstat(descriptor)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
    )
    if identity(before) != identity(after):
        die(f"{label} descriptor changed while read")
    return bytes(content)


def executable_binding(path: Path) -> dict[str, Any]:
    path = path.resolve(strict=True)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        content = descriptor_bytes(descriptor, executable=True, label=str(path))
    finally:
        os.close(descriptor)
    return {"path": str(path), "sha256": sha256(content), "bytes": len(content)}


def inherited_executable_binding(descriptor: int, path: Path) -> tuple[dict[str, Any], bytes]:
    canonical = path.resolve(strict=True)
    if canonical != path or path.is_symlink():
        die("release binary path must be canonical and non-symlinked")
    descriptor_path = Path(f"/proc/self/fd/{descriptor}")
    if not descriptor_path.exists():
        die("inherited release binary descriptor is unavailable")
    try:
        descriptor_target = descriptor_path.resolve(strict=True)
    except OSError as error:
        die(f"cannot resolve inherited release binary descriptor: {error}")
    if descriptor_target != canonical:
        die("inherited release descriptor does not name the attested binary path")
    content = descriptor_bytes(descriptor, executable=True, label="release binary")
    return (
        {
            "path": str(canonical),
            "sha256": sha256(content),
            "bytes": len(content),
            "attestation": "inherited-open-descriptor.v1",
        },
        content,
    )


def _elf_string(table: bytes, offset: int, label: str) -> str:
    if offset < 0 or offset >= len(table):
        die(f"ELF {label} string offset is out of bounds")
    end = table.find(b"\0", offset)
    if end < 0:
        die(f"ELF {label} string is not NUL terminated")
    try:
        value = table[offset:end].decode("ascii")
    except UnicodeDecodeError as error:
        die(f"ELF {label} string is not ASCII: {error}")
    if not value or "\n" in value or "\r" in value:
        die(f"ELF {label} string is malformed")
    return value


def parse_linux_elf(content: bytes, *, label: str) -> dict[str, Any]:
    if len(content) < 64 or content[:4] != b"\x7fELF":
        die(f"{label} is not an ELF file")
    identity = content[:16]
    if identity[4] != 2 or identity[5] != 1 or identity[6] != 1:
        die(f"{label} must be a little-endian ELF64 version-1 image")
    (
        elf_type,
        machine,
        version,
        _entry,
        program_offset,
        _section_offset,
        _flags,
        header_size,
        program_entry_size,
        program_count,
        _section_entry_size,
        _section_count,
        _section_names,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", content, 16)
    if (
        version != 1
        or header_size != 64
        or program_entry_size != 56
        or program_count < 1
        or program_count > 4096
        or program_offset + program_entry_size * program_count > len(content)
    ):
        die(f"{label} has a malformed ELF header or program table")
    machine_names = {62: "x86_64", 183: "aarch64"}
    if machine not in machine_names:
        die(f"{label} uses unsupported ELF machine {machine}")
    type_names = {2: "executable", 3: "shared-or-pie"}
    if elf_type not in type_names:
        die(f"{label} uses unsupported ELF type {elf_type}")

    programs: list[dict[str, int]] = []
    for index in range(program_count):
        values = struct.unpack_from(
            "<IIQQQQQQ", content, program_offset + index * program_entry_size
        )
        program = dict(
            zip(
                ("type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz", "align"),
                values,
                strict=True,
            )
        )
        if program["filesz"] > program["memsz"]:
            die(f"{label} has an ELF segment larger on disk than in memory")
        if program["offset"] + program["filesz"] > len(content):
            die(f"{label} has an ELF segment outside the file")
        programs.append(program)

    interpreters = [program for program in programs if program["type"] == 3]
    if len(interpreters) > 1:
        die(f"{label} has multiple PT_INTERP segments")
    interpreter = None
    if interpreters:
        program = interpreters[0]
        raw = content[program["offset"] : program["offset"] + program["filesz"]]
        if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
            die(f"{label} has a malformed PT_INTERP value")
        interpreter = _elf_string(raw, 0, "interpreter")
        if not interpreter.startswith("/"):
            die(f"{label} has a nonabsolute PT_INTERP value")

    dynamic_segments = [program for program in programs if program["type"] == 2]
    if len(dynamic_segments) > 1:
        die(f"{label} has multiple PT_DYNAMIC segments")
    dynamic: list[tuple[int, int]] = []
    if dynamic_segments:
        segment = dynamic_segments[0]
        if segment["filesz"] % 16:
            die(f"{label} has a misaligned PT_DYNAMIC segment")
        terminated = False
        for offset in range(
            segment["offset"], segment["offset"] + segment["filesz"], 16
        ):
            tag, value = struct.unpack_from("<qQ", content, offset)
            if tag == 0:
                terminated = True
                break
            dynamic.append((tag, value))
        if not terminated:
            die(f"{label} has an unterminated PT_DYNAMIC segment")

    def one_dynamic(tag: int, name: str, *, required: bool = False) -> int | None:
        values = [value for candidate, value in dynamic if candidate == tag]
        if len(values) > 1 or (required and len(values) != 1):
            die(f"{label} has an invalid {name} dynamic entry count")
        return values[0] if values else None

    needed_offsets = [value for tag, value in dynamic if tag == 1]
    string_address = one_dynamic(5, "DT_STRTAB", required=bool(dynamic))
    string_size = one_dynamic(10, "DT_STRSZ", required=bool(dynamic))
    string_table = b""
    if dynamic:
        assert string_address is not None and string_size is not None
        string_offset = None
        for program in programs:
            if program["type"] != 1:
                continue
            delta = string_address - program["vaddr"]
            if 0 <= delta and delta + string_size <= program["filesz"]:
                string_offset = program["offset"] + delta
                break
        if string_offset is None or string_offset + string_size > len(content):
            die(f"{label} DT_STRTAB does not map to a file-backed PT_LOAD segment")
        string_table = content[string_offset : string_offset + string_size]

    def dynamic_strings(tag: int, name: str) -> list[str]:
        return [
            _elf_string(string_table, value, name)
            for candidate, value in dynamic
            if candidate == tag
        ]

    needed = dynamic_strings(1, "DT_NEEDED")
    if len(needed) != len(set(needed)):
        die(f"{label} has duplicate DT_NEEDED entries")
    sonames = dynamic_strings(14, "DT_SONAME")
    rpaths = dynamic_strings(15, "DT_RPATH")
    runpaths = dynamic_strings(29, "DT_RUNPATH")
    if len(sonames) > 1 or len(rpaths) > 1 or len(runpaths) > 1:
        die(f"{label} has duplicate ELF identity or search-path entries")
    return {
        "abi_version": identity[8],
        "class": "ELF64",
        "endianness": "little",
        "interpreter": interpreter,
        "machine": machine_names[machine],
        "needed": needed,
        "osabi": identity[7],
        "rpath": [] if not rpaths else rpaths[0].split(":"),
        "runpath": [] if not runpaths else runpaths[0].split(":"),
        "soname": sonames[0] if sonames else None,
        "type": type_names[elf_type],
    }


def _runtime_object(path: Path) -> tuple[Path, bytes, dict[str, Any]]:
    canonical = path.resolve(strict=True)
    descriptor = os.open(canonical, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        content = descriptor_bytes(descriptor, executable=False, label=str(canonical))
    finally:
        os.close(descriptor)
    return canonical, content, parse_linux_elf(content, label=str(canonical))


def _expanded_elf_search_paths(values: list[str], origin: Path) -> list[Path]:
    paths: list[Path] = []
    for value in values:
        expanded = value.replace("${ORIGIN}", str(origin)).replace("$ORIGIN", str(origin))
        if "$" in expanded:
            die(f"unsupported ELF dynamic search token in {value!r}")
        candidate = Path(expanded)
        if not candidate.is_absolute():
            die(f"relative ELF dynamic search path is forbidden: {value!r}")
        if candidate.is_dir():
            paths.append(candidate.resolve(strict=True))
    return paths


def attest_linux_elf(
    binary_path: Path, binary_content: bytes, binary_binding: dict[str, Any]
) -> dict[str, Any]:
    if not sys.platform.startswith("linux"):
        die("Linux ELF provenance is required for a guarded T1 release")
    root_elf = parse_linux_elf(binary_content, label=str(binary_path))
    interpreter_name = root_elf["interpreter"]
    if interpreter_name is None:
        die("guarded T1 release ELF has no PT_INTERP")
    interpreter_path, interpreter_content, interpreter_elf = _runtime_object(
        Path(interpreter_name)
    )
    if interpreter_elf["machine"] != root_elf["machine"]:
        die("ELF interpreter machine differs from the release binary")

    triplet = {"x86_64": "x86_64-linux-gnu", "aarch64": "aarch64-linux-gnu"}[
        root_elf["machine"]
    ]
    default_candidates = [
        interpreter_path.parent,
        Path("/lib64"),
        Path("/usr/lib64"),
        Path("/lib") / triplet,
        Path("/usr/lib") / triplet,
        Path("/lib"),
        Path("/usr/lib"),
    ]
    default_search: list[Path] = []
    for candidate in default_candidates:
        if candidate.is_dir():
            canonical = candidate.resolve(strict=True)
            if canonical not in default_search:
                default_search.append(canonical)
    if not default_search:
        die("no canonical native runtime search directories are available")

    object_data: dict[Path, tuple[bytes, dict[str, Any], str]] = {
        binary_path: (binary_content, root_elf, "binary"),
        interpreter_path: (interpreter_content, interpreter_elf, "interpreter"),
    }
    pending = [binary_path, interpreter_path]
    edges: list[dict[str, str]] = []
    while pending:
        source = pending.pop(0)
        _, elf, _ = object_data[source]
        dynamic_search = _expanded_elf_search_paths(
            elf["runpath"] if elf["runpath"] else elf["rpath"], source.parent
        )
        search = [*dynamic_search, *default_search]
        for needed in elf["needed"]:
            if "/" in needed or needed in {".", ".."}:
                die(f"unsafe DT_NEEDED name in {source}: {needed!r}")
            resolved: Path | None = None
            for directory in search:
                candidate = directory / needed
                if candidate.exists():
                    resolved = candidate.resolve(strict=True)
                    break
            if resolved is None:
                die(f"cannot resolve DT_NEEDED {needed!r} from {source}")
            if resolved not in object_data:
                path, content, dependency_elf = _runtime_object(resolved)
                if dependency_elf["machine"] != root_elf["machine"]:
                    die(f"native dependency machine mismatch: {path}")
                object_data[path] = (content, dependency_elf, "dependency")
                pending.append(path)
            edges.append({"needed": needed, "resolved": str(resolved), "source": str(source)})

    objects = [
        {
            "bytes": len(content),
            "elf": elf,
            "path": str(path),
            "role": role,
            "sha256": sha256(content),
        }
        for path, (content, elf, role) in sorted(object_data.items(), key=lambda item: str(item[0]))
    ]
    edges.sort(key=lambda edge: (edge["source"], edge["needed"], edge["resolved"]))
    closure = {"edges": edges, "objects": objects}
    return {
        "schema": "euf-viper.t1-linux-elf-provenance.v1",
        "binary_sha256": binary_binding["sha256"],
        "closure_sha256": sha256(canonical_bytes(closure)),
        "default_search": [str(path) for path in default_search],
        "edges": edges,
        "interpreter": {
            "bytes": len(interpreter_content),
            "path": str(interpreter_path),
            "requested": interpreter_name,
            "sha256": sha256(interpreter_content),
        },
        "objects": objects,
    }


def linked_libc_identity(provenance: dict[str, Any]) -> dict[str, Any]:
    candidates = [
        item
        for item in provenance["objects"]
        if (item["elf"]["soname"] or Path(item["path"]).name).startswith("libc.so")
    ]
    if len(candidates) != 1:
        die("ELF closure does not contain exactly one libc identity")
    candidate = candidates[0]
    name, version = platform.libc_ver()
    if not name or not version:
        die("cannot identify libc name and version")
    return {
        "path": candidate["path"],
        "sha256": candidate["sha256"],
        "bytes": candidate["bytes"],
        "name": name,
        "version": version,
    }


def validate_selected_linker(cc: dict[str, Any], linker: dict[str, Any]) -> dict[str, Any]:
    completed = subprocess.run(
        [cc["path"], "-fuse-ld=bfd", "-print-prog-name=ld"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )
    try:
        reported = completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as error:
        die(f"C compiler reported a non-ASCII linker path: {error}")
    if not reported or "\n" in reported or "\r" in reported:
        die("C compiler did not report exactly one linker path")
    candidate = Path(reported)
    if not candidate.is_absolute():
        matches = {
            (directory / candidate).resolve(strict=True)
            for directory in (Path("/usr/bin"), Path("/bin"))
            if (directory / candidate).is_file()
        }
        if len(matches) != 1:
            die(f"cannot resolve C compiler selected linker: {reported}")
        candidate = next(iter(matches))
    if candidate.resolve(strict=True) != Path(linker["path"]):
        die("C compiler selected linker differs from the pinned linker identity")
    return {
        "driver_path": cc["path"],
        "driver_sha256": cc["sha256"],
        "request": "-fuse-ld=bfd",
        "resolved_path": linker["path"],
        "resolved_sha256": linker["sha256"],
    }


def validate_clean_monitor(
    receipt_path: Path,
    receipt_descriptor: int,
    events_path: Path,
    events_descriptor: int,
    expected_root: str,
    label: str,
) -> tuple[dict[str, Any], bytes]:
    monitor, receipt_content = load_canonical_descriptor(
        receipt_descriptor, receipt_path, f"{label} monitor receipt"
    )
    if (
        monitor.get("schema") != "euf-viper.t1-mutation-monitor-receipt.v2"
        or monitor.get("control") != "parent-owned-pipe-eof.v1"
        or not isinstance(monitor.get("monitor_pid"), int)
        or monitor.get("monitor_pid", 0) <= 1
        or not isinstance(monitor.get("parent_pid"), int)
        or monitor.get("parent_pid", 0) <= 1
        or not isinstance(monitor.get("poll_cycles"), int)
        or monitor.get("poll_cycles", 0) < 1
        or monitor.get("status") != "clean"
        or monitor.get("event_count") != 0
    ):
        die(f"{label} mutation monitor did not close cleanly")
    if monitor.get("snapshot") != expected_root:
        die(f"{label} monitor and inventory root identities differ")
    events = monitor.get("events")
    if not isinstance(events, dict) or set(events) != {"path", "sha256", "bytes"}:
        die(f"{label} mutation monitor event binding is malformed")
    if events.get("path") != str(events_path):
        die(f"{label} mutation monitor event path binding differs")
    require_descriptor_path(
        events_descriptor, events_path, f"{label} mutation event log"
    )
    if stat.S_IMODE(os.fstat(events_descriptor).st_mode) != 0o400:
        die(f"{label} mutation monitor event log is not sealed mode 0400")
    events_content = descriptor_bytes(
        events_descriptor, executable=False, label=f"{label} mutation event log"
    )
    if (
        events_content
        or len(events_content) != events["bytes"]
        or sha256(events_content) != events["sha256"]
    ):
        die(f"clean {label} mutation monitor event log is not empty and bound")
    return monitor, receipt_content


def receipt_command(args: argparse.Namespace) -> None:
    pre, pre_content = load_canonical_descriptor(
        args.pre_inventory_fd, args.pre_inventory, "pre-build source inventory"
    )
    post, post_content = load_canonical_descriptor(
        args.post_inventory_fd, args.post_inventory, "post-build source inventory"
    )
    dependency_pre, dependency_pre_content = load_canonical_descriptor(
        args.dependency_pre_inventory_fd,
        args.dependency_pre_inventory,
        "pre-build dependency inventory",
    )
    dependency_post, dependency_post_content = load_canonical_descriptor(
        args.dependency_post_inventory_fd,
        args.dependency_post_inventory,
        "post-build dependency inventory",
    )
    if pre != post:
        die("pre-build and post-build source inventories differ")
    monitor, monitor_content = validate_clean_monitor(
        args.monitor_receipt,
        args.monitor_receipt_fd,
        args.monitor_events,
        args.monitor_events_fd,
        pre.get("snapshot"),
        "source",
    )
    if dependency_pre != dependency_post:
        die("pre-build and post-build dependency inventories differ")
    if dependency_pre.get("schema") != "euf-viper.t1-external-dependency-inventory.v1":
        die("dependency inventory schema mismatch")
    dependency_monitor, dependency_monitor_content = validate_clean_monitor(
        args.dependency_monitor_receipt,
        args.dependency_monitor_receipt_fd,
        args.dependency_monitor_events,
        args.dependency_monitor_events_fd,
        dependency_pre.get("root"),
        "dependency",
    )
    snapshot = Path(pre["snapshot"]).resolve(strict=True)
    cargo_home = args.cargo_home.resolve(strict=True)
    fetch_cargo_home = args.fetch_cargo_home.resolve(strict=True)
    target_dir = args.target_dir.resolve(strict=True)
    dependency_root = Path(dependency_pre["root"]).resolve(strict=True)
    vendor_dir = args.vendor_dir.resolve(strict=True)
    for path in (cargo_home, fetch_cargo_home, target_dir, dependency_root, vendor_dir):
        if path.is_relative_to(snapshot):
            die("build inputs and outputs must remain outside the watched source snapshot")
    if vendor_dir != dependency_root / "vendor":
        die("vendored dependency directory is not rooted in the bound dependency tree")
    tools: dict[str, Any] = {}
    for name in ("ar", "cargo", "cc", "ld", "rustc"):
        prefix = f"EUF_VIPER_{name.upper()}"
        binding = executable_binding(Path(os.environ[f"{prefix}"]))
        expected_hash = os.environ[f"{prefix}_SHA256"]
        version = os.environ[f"{prefix}_VERSION"]
        if binding["sha256"] != expected_hash:
            die(f"{name} executable hash mismatch")
        binding["version"] = version
        tools[name] = binding
    linker_selection = validate_selected_linker(tools["cc"], tools["ld"])
    python_binding = executable_binding(Path(os.environ["EUF_VIPER_PYTHON"]))
    if python_binding["sha256"] != os.environ["EUF_VIPER_PYTHON_SHA256"]:
        die("Python executable hash mismatch")
    python_binding["version"] = os.environ["EUF_VIPER_PYTHON_VERSION"]
    binary, binary_content = inherited_executable_binding(args.binary_fd, args.binary)
    elf_provenance = attest_linux_elf(args.binary, binary_content, binary)
    payload = {
        "schema": "euf-viper.t1-guarded-release-build.v2",
        "status": "clean",
        "revision": valid_revision(args.revision),
        "source_snapshot": pre["snapshot"],
        "pre_inventory": {
            "path": str(args.pre_inventory),
            "sha256": sha256(pre_content),
            "payload": pre,
        },
        "post_inventory": {
            "path": str(args.post_inventory),
            "sha256": sha256(post_content),
            "payload": post,
        },
        "mutation_monitor": {
            "path": str(args.monitor_receipt),
            "sha256": sha256(monitor_content),
            "payload": monitor,
        },
        "dependency_pre_inventory": {
            "path": str(args.dependency_pre_inventory),
            "sha256": sha256(dependency_pre_content),
            "payload": dependency_pre,
        },
        "dependency_post_inventory": {
            "path": str(args.dependency_post_inventory),
            "sha256": sha256(dependency_post_content),
            "payload": dependency_post,
        },
        "dependency_mutation_monitor": {
            "path": str(args.dependency_monitor_receipt),
            "sha256": sha256(dependency_monitor_content),
            "payload": dependency_monitor,
        },
        "binary": binary,
        "linux_elf": elf_provenance,
        "linker_selection": linker_selection,
        "python": python_binding,
        "tools": tools,
        "libc": linked_libc_identity(elf_provenance),
        "build": {
            "allocator": "system-libc",
            "backend": "auto",
            "cargo_home": str(cargo_home),
            "cargo_profile": "release",
            "dependency_mode": "locked-vendor-offline-v1",
            "features": ["finite-symmetry"],
            "fetch_cargo_home": str(fetch_cargo_home),
            "locked": True,
            "offline": True,
            "rustflags": f"-C linker={tools['cc']['path']} -C link-arg=-fuse-ld=bfd",
            "target_dir": str(target_dir),
            "vendor_dir": str(vendor_dir),
        },
    }
    if pre.get("revision") != payload["revision"]:
        die("build receipt revision differs from inventory")
    publish_descriptor(
        args.output_fd,
        args.output,
        canonical_bytes(payload),
        "guarded build receipt",
    )


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(description=__doc__)
    commands = top.add_subparsers(dest="command", required=True)
    check = commands.add_parser("inventory")
    check.add_argument("--repository", type=Path, required=True)
    check.add_argument("--revision", required=True)
    check.add_argument("--snapshot", type=Path, required=True)
    check.add_argument("--output", type=Path, required=True)
    dependency = commands.add_parser("inventory-tree")
    dependency.add_argument("--root", type=Path, required=True)
    dependency.add_argument("--output", type=Path, required=True)
    monitor = commands.add_parser("monitor")
    monitor.add_argument("--snapshot", type=Path, required=True)
    monitor.add_argument("--ready", type=Path, required=True)
    monitor.add_argument("--ready-fd", type=int, required=True)
    monitor.add_argument("--control-fd", type=int, required=True)
    monitor.add_argument("--events", type=Path, required=True)
    monitor.add_argument("--events-fd", type=int, required=True)
    monitor.add_argument("--receipt", type=Path, required=True)
    monitor.add_argument("--receipt-fd", type=int, required=True)
    receipt = commands.add_parser("receipt")
    receipt.add_argument("--revision", required=True)
    receipt.add_argument("--pre-inventory", type=Path, required=True)
    receipt.add_argument("--pre-inventory-fd", type=int, required=True)
    receipt.add_argument("--post-inventory", type=Path, required=True)
    receipt.add_argument("--post-inventory-fd", type=int, required=True)
    receipt.add_argument("--monitor-receipt", type=Path, required=True)
    receipt.add_argument("--monitor-receipt-fd", type=int, required=True)
    receipt.add_argument("--monitor-events", type=Path, required=True)
    receipt.add_argument("--monitor-events-fd", type=int, required=True)
    receipt.add_argument("--dependency-pre-inventory", type=Path, required=True)
    receipt.add_argument("--dependency-pre-inventory-fd", type=int, required=True)
    receipt.add_argument("--dependency-post-inventory", type=Path, required=True)
    receipt.add_argument("--dependency-post-inventory-fd", type=int, required=True)
    receipt.add_argument("--dependency-monitor-receipt", type=Path, required=True)
    receipt.add_argument("--dependency-monitor-receipt-fd", type=int, required=True)
    receipt.add_argument("--dependency-monitor-events", type=Path, required=True)
    receipt.add_argument("--dependency-monitor-events-fd", type=int, required=True)
    receipt.add_argument("--binary", type=Path, required=True)
    receipt.add_argument("--binary-fd", type=int, required=True)
    receipt.add_argument("--cargo-home", type=Path, required=True)
    receipt.add_argument("--fetch-cargo-home", type=Path, required=True)
    receipt.add_argument("--target-dir", type=Path, required=True)
    receipt.add_argument("--vendor-dir", type=Path, required=True)
    receipt.add_argument("--output", type=Path, required=True)
    receipt.add_argument("--output-fd", type=int, required=True)
    return top


def main() -> int:
    args = parser().parse_args()
    if args.command == "inventory":
        inventory_command(args)
    elif args.command == "inventory-tree":
        external_tree_inventory_command(args)
    elif args.command == "monitor":
        monitor_command(args)
    elif args.command == "receipt":
        receipt_command(args)
    else:
        raise AssertionError(args.command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
