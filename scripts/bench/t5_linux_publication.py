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


AT_SYMLINK_FOLLOW = 0x400
PROC_SUPER_MAGIC = 0x9FA0
PROC_SELF_FD = "/proc/self/fd"
READ_CHUNK = 1024 * 1024

CAPABILITY_NAMES = (
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
)


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


class _StatFs(ctypes.Structure):
    _fields_ = (
        ("f_type", ctypes.c_long),
        ("f_bsize", ctypes.c_long),
        ("f_blocks", ctypes.c_ulong),
        ("f_bfree", ctypes.c_ulong),
        ("f_bavail", ctypes.c_ulong),
        ("f_files", ctypes.c_ulong),
        ("f_ffree", ctypes.c_ulong),
        ("f_fsid", ctypes.c_int * 2),
        ("f_namelen", ctypes.c_long),
        ("f_frsize", ctypes.c_long),
        ("f_flags", ctypes.c_long),
        ("f_spare", ctypes.c_long * 4),
    )


def statfs_properties(descriptor: int) -> dict[str, int]:
    libc = ctypes.CDLL(None, use_errno=True)
    fstatfs = libc.fstatfs
    fstatfs.argtypes = (ctypes.c_int, ctypes.POINTER(_StatFs))
    fstatfs.restype = ctypes.c_int
    value = _StatFs()
    if fstatfs(descriptor, ctypes.byref(value)) != 0:
        error = ctypes.get_errno()
        raise PublicationError(f"cannot inspect filesystem type: {os.strerror(error)}")
    return {
        "type": int(value.f_type),
        "block_size": int(value.f_bsize),
        "name_length": int(value.f_namelen),
        "fragment_size": int(value.f_frsize),
        "flags": int(value.f_flags),
    }


def _read_proc_text(path: str, maximum_bytes: int) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PublicationError(f"cannot open Linux process metadata {path}: {error}") from error
    try:
        payload = read_fd(descriptor, maximum_bytes=maximum_bytes)
    finally:
        os.close(descriptor)
    try:
        return payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise PublicationError(f"Linux process metadata is not ASCII: {path}") from error


def linux_capability_inventory() -> dict[str, object]:
    if not sys.platform.startswith("linux"):
        raise PublicationError("Linux capability inventory requires Linux procfs")
    status = _read_proc_text("/proc/self/status", 1024 * 1024)
    values: dict[str, str] = {}
    for line in status.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key] = value.strip()
    fields = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    if any(field not in values for field in fields):
        raise PublicationError("/proc/self/status lacks a complete capability inventory")
    try:
        numeric = {field: int(values[field], 16) for field in fields}
        last_cap = int(_read_proc_text("/proc/sys/kernel/cap_last_cap", 128).strip())
    except ValueError as error:
        raise PublicationError("Linux capability metadata is malformed") from error
    if not 0 <= last_cap < 4096:
        raise PublicationError("Linux cap_last_cap is outside its supported bound")

    def names(bits: int) -> list[str]:
        return [
            CAPABILITY_NAMES[index]
            if index < len(CAPABILITY_NAMES)
            else f"CAP_{index}"
            for index in range(last_cap + 1)
            if bits & (1 << index)
        ]

    inventory = {
        "uid": os.getuid(),
        "effective_uid": os.geteuid(),
        "gid": os.getgid(),
        "effective_gid": os.getegid(),
        "last_capability": last_cap,
        "sets": {
            field: {
                "hex": f"{numeric[field]:016x}",
                "names": names(numeric[field]),
            }
            for field in fields
        },
        "cap_dac_read_search_effective": bool(numeric["CapEff"] & (1 << 2)),
    }
    validate_linux_capability_inventory(inventory)
    return inventory


def validate_linux_capability_inventory(value: object) -> dict[str, object]:
    required = {
        "uid",
        "effective_uid",
        "gid",
        "effective_gid",
        "last_capability",
        "sets",
        "cap_dac_read_search_effective",
    }
    if type(value) is not dict or set(value) != required:
        raise PublicationError("Linux capability inventory field set drift")
    for field in ("uid", "effective_uid", "gid", "effective_gid"):
        if type(value[field]) is not int or value[field] < 0:
            raise PublicationError("Linux capability identity is malformed")
    last_capability = value["last_capability"]
    if type(last_capability) is not int or not 0 <= last_capability < 4096:
        raise PublicationError("Linux last-capability value is malformed")
    sets = value["sets"]
    set_names = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    if type(sets) is not dict or set(sets) != set(set_names):
        raise PublicationError("Linux capability sets are incomplete")
    numeric: dict[str, int] = {}
    for set_name in set_names:
        row = sets[set_name]
        if type(row) is not dict or set(row) != {"hex", "names"}:
            raise PublicationError("Linux capability-set record is malformed")
        hexadecimal = row["hex"]
        names = row["names"]
        if (
            type(hexadecimal) is not str
            or len(hexadecimal) < 16
            or any(character not in "0123456789abcdef" for character in hexadecimal)
            or type(names) is not list
            or any(type(name) is not str for name in names)
        ):
            raise PublicationError("Linux capability-set value is malformed")
        bits = int(hexadecimal, 16)
        if bits >> (last_capability + 1):
            raise PublicationError("Linux capability set exceeds cap_last_cap")
        expected_names = [
            CAPABILITY_NAMES[index]
            if index < len(CAPABILITY_NAMES)
            else f"CAP_{index}"
            for index in range(last_capability + 1)
            if bits & (1 << index)
        ]
        if names != expected_names:
            raise PublicationError("Linux capability names differ from their bit set")
        numeric[set_name] = bits
    expected_dac = bool(numeric["CapEff"] & (1 << 2))
    if value["cap_dac_read_search_effective"] is not expected_dac:
        raise PublicationError("CAP_DAC_READ_SEARCH effective flag drift")
    return value


def _verified_proc_fd_directory(
    source_descriptor: int,
) -> tuple[int, dict[str, object]]:
    if not sys.platform.startswith("linux"):
        raise PublicationError("T5 publication requires Linux procfs")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        proc_descriptor = os.open(PROC_SELF_FD, flags)
    except OSError as error:
        raise PublicationError(f"cannot pin {PROC_SELF_FD}: {error}") from error
    try:
        properties = statfs_properties(proc_descriptor)
        if properties["type"] != PROC_SUPER_MAGIC:
            raise PublicationError(f"{PROC_SELF_FD} is not a procfs descriptor directory")
        source_stat = os.fstat(source_descriptor)
        descriptor_name = str(source_descriptor)
        link_stat = os.stat(
            descriptor_name, dir_fd=proc_descriptor, follow_symlinks=False
        )
        target_stat = os.stat(
            descriptor_name, dir_fd=proc_descriptor, follow_symlinks=True
        )
        if not stat.S_ISLNK(link_stat.st_mode) or not _same_inode(source_stat, target_stat):
            raise PublicationError(
                "/proc/self/fd does not expose the expected descriptor symlink semantics"
            )
        target = os.readlink(descriptor_name, dir_fd=proc_descriptor)
        if not target or "\x00" in target:
            raise PublicationError("/proc/self/fd descriptor target is malformed")
        return proc_descriptor, {
            "method": "proc_self_fd_linkat_at_symlink_follow",
            "proc_self_fd": PROC_SELF_FD,
            "procfs": properties,
            "descriptor_symlink_verified": True,
            "capabilities": linux_capability_inventory(),
        }
    except BaseException:
        os.close(proc_descriptor)
        raise


def capture_publication_environment(probe_descriptor: int) -> dict[str, object]:
    proc_descriptor, evidence = _verified_proc_fd_directory(probe_descriptor)
    os.close(proc_descriptor)
    return evidence


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
    source_directory_descriptor: int,
    source_name: bytes,
    destination_directory_descriptor: int,
    destination_name: str,
    flags: int,
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
            source_directory_descriptor,
            source_name,
            destination_directory_descriptor,
            os.fsencode(destination_name),
            flags,
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
    proc_descriptor, _ = _verified_proc_fd_directory(source_descriptor)
    try:
        error = _call_linkat(
            proc_descriptor,
            os.fsencode(str(source_descriptor)),
            directory_descriptor,
            destination_name,
            AT_SYMLINK_FOLLOW,
        )
    finally:
        os.close(proc_descriptor)
    if error == errno.EEXIST:
        raise PublicationError(
            f"publication destination already exists: {destination_name}"
        )
    if error:
        raise PublicationError(
            "cannot link O_TMPFILE through verified /proc/self/fd semantics: "
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
        os.fsync(descriptor)
        after_fsync = os.fstat(descriptor)
        named_after_fsync = os.stat(
            name, dir_fd=directory_descriptor, follow_symlinks=False
        )
        if (
            not _same_inode(descriptor_stat, after_fsync)
            or not _same_inode(after_fsync, named_after_fsync)
            or after_fsync.st_nlink != 1
            or stat.S_IMODE(after_fsync.st_mode) != 0o444
            or after_fsync.st_size != descriptor_stat.st_size
        ):
            raise PublicationError("published inode or final path changed after fsync")
        first_digest = sha256_fd(descriptor)
        if first_digest != expected_sha256:
            raise PublicationError("published inode SHA-256 mismatch after fsync")
        if expected_payload is not None and read_fd(
            descriptor, maximum_bytes=len(expected_payload)
        ) != expected_payload:
            raise PublicationError("published inode content mismatch after fsync")
        final_stat = os.fstat(descriptor)
        final_named = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        final_digest = sha256_fd(descriptor)
        terminal_stat = os.fstat(descriptor)
        terminal_named = os.stat(
            name, dir_fd=directory_descriptor, follow_symlinks=False
        )
        if (
            not _same_inode(after_fsync, final_stat)
            or not _same_inode(final_stat, final_named)
            or not _same_inode(final_stat, terminal_stat)
            or not _same_inode(terminal_stat, terminal_named)
            or final_stat.st_nlink != 1
            or terminal_stat.st_nlink != 1
            or final_stat.st_size != after_fsync.st_size
            or terminal_stat.st_size != final_stat.st_size
            or final_digest != expected_sha256
            or expected_descriptor is not None
            and not _same_inode(terminal_stat, os.fstat(expected_descriptor))
        ):
            raise PublicationError(
                "published inode, digest, link count, or final path changed after fsync"
            )
        return terminal_stat
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
