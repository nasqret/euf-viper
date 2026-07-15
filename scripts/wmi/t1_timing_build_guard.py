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
    descriptor = inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
    if descriptor < 0:
        error = ctypes.get_errno()
        die(f"inotify_init1 failed: {os.strerror(error)}")
    watches: dict[int, Path] = {}
    try:
        for directory in all_directories(snapshot):
            watch = inotify_add_watch(descriptor, os.fsencode(directory), WATCH_MASK)
            if watch < 0:
                error = ctypes.get_errno()
                die(f"inotify_add_watch failed for {directory}: {os.strerror(error)}")
            watches[watch] = directory
        events_descriptor = os.open(
            args.events,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        events_digest = hashlib.sha256()
        event_count = 0
        ready = {
            "schema": "euf-viper.t1-mutation-monitor-ready.v1",
            "snapshot": str(snapshot),
            "watched_directories": len(watches),
            "watch_mask": WATCH_MASK,
        }
        publish(args.ready, canonical_bytes(ready))
        poller = select.poll()
        poller.register(descriptor, select.POLLIN)
        try:
            while not args.stop.exists():
                for _, _ in poller.poll(50):
                    data = os.read(descriptor, 1024 * 1024)
                    offset = 0
                    while offset < len(data):
                        watch, mask, cookie, length = struct.unpack_from("iIII", data, offset)
                        offset += 16
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
            while True:
                ready_events = poller.poll(25)
                if not ready_events:
                    break
                data = os.read(descriptor, 1024 * 1024)
                if not data:
                    break
                offset = 0
                while offset < len(data):
                    watch, mask, cookie, length = struct.unpack_from("iIII", data, offset)
                    offset += 16
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
            os.fchmod(events_descriptor, 0o400)
            os.fsync(events_descriptor)
        finally:
            os.close(events_descriptor)
        receipt = {
            "schema": "euf-viper.t1-mutation-monitor-receipt.v1",
            "snapshot": str(snapshot),
            "watched_directories": len(watches),
            "watch_mask": WATCH_MASK,
            "event_count": event_count,
            "events": {
                "path": str(args.events.resolve(strict=True)),
                "sha256": events_digest.hexdigest(),
                "bytes": args.events.stat().st_size,
            },
            "status": "clean" if event_count == 0 else "mutated",
        }
        publish(args.receipt, canonical_bytes(receipt))
        if event_count:
            raise SystemExit(3)
    finally:
        os.close(descriptor)


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


def executable_binding(path: Path) -> dict[str, Any]:
    path = path.resolve(strict=True)
    metadata = path.stat()
    if not path.is_file() or path.is_symlink() or metadata.st_mode & 0o111 == 0:
        die(f"not a regular executable: {path}")
    content = path.read_bytes()
    return {"path": str(path), "sha256": sha256(content), "bytes": len(content)}


def linked_libc_identity(binary: Path) -> dict[str, Any]:
    completed = subprocess.run(
        ["/usr/bin/ldd", str(binary.resolve(strict=True))],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        text=True,
    )
    candidates: set[Path] = set()
    for line in completed.stdout.splitlines():
        fields = line.split()
        if fields and fields[0].startswith("libc.so"):
            if len(fields) < 3 or fields[1] != "=>" or not fields[2].startswith("/"):
                die(f"malformed libc dependency from ldd: {line}")
            candidates.add(Path(fields[2]).resolve(strict=True))
    if len(candidates) != 1:
        die(f"cannot identify exactly one linked libc: {sorted(map(str, candidates))}")
    path = next(iter(candidates))
    content = path.read_bytes()
    name, version = platform.libc_ver()
    if not name or not version:
        die("cannot identify libc name and version")
    return {
        "path": str(path),
        "sha256": sha256(content),
        "bytes": len(content),
        "name": name,
        "version": version,
    }


def validate_selected_linker(cc: dict[str, Any], linker: dict[str, Any]) -> None:
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


def validate_clean_monitor(path: Path, expected_root: str, label: str) -> dict[str, Any]:
    monitor = load_canonical(path)
    if monitor.get("status") != "clean" or monitor.get("event_count") != 0:
        die(f"{label} mutation monitor did not close cleanly")
    if monitor.get("snapshot") != expected_root:
        die(f"{label} monitor and inventory root identities differ")
    events = monitor.get("events")
    if not isinstance(events, dict) or set(events) != {"path", "sha256", "bytes"}:
        die(f"{label} mutation monitor event binding is malformed")
    events_path = Path(events["path"]).resolve(strict=True)
    if stat.S_IMODE(events_path.stat().st_mode) != 0o400:
        die(f"{label} mutation monitor event log is not sealed mode 0400")
    events_content = events_path.read_bytes()
    if (
        events_content
        or len(events_content) != events["bytes"]
        or sha256(events_content) != events["sha256"]
    ):
        die(f"clean {label} mutation monitor event log is not empty and bound")
    return monitor


def receipt_command(args: argparse.Namespace) -> None:
    pre = load_canonical(args.pre_inventory)
    post = load_canonical(args.post_inventory)
    dependency_pre = load_canonical(args.dependency_pre_inventory)
    dependency_post = load_canonical(args.dependency_post_inventory)
    if pre != post:
        die("pre-build and post-build source inventories differ")
    monitor = validate_clean_monitor(
        args.monitor_receipt, pre.get("snapshot"), "source"
    )
    if dependency_pre != dependency_post:
        die("pre-build and post-build dependency inventories differ")
    if dependency_pre.get("schema") != "euf-viper.t1-external-dependency-inventory.v1":
        die("dependency inventory schema mismatch")
    dependency_monitor = validate_clean_monitor(
        args.dependency_monitor_receipt, dependency_pre.get("root"), "dependency"
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
    validate_selected_linker(tools["cc"], tools["ld"])
    python_binding = executable_binding(Path(os.environ["EUF_VIPER_PYTHON"]))
    if python_binding["sha256"] != os.environ["EUF_VIPER_PYTHON_SHA256"]:
        die("Python executable hash mismatch")
    python_binding["version"] = os.environ["EUF_VIPER_PYTHON_VERSION"]
    binary = executable_binding(args.binary)
    payload = {
        "schema": "euf-viper.t1-guarded-release-build.v1",
        "status": "clean",
        "revision": valid_revision(args.revision),
        "source_snapshot": pre["snapshot"],
        "pre_inventory": {
            "path": str(args.pre_inventory.resolve(strict=True)),
            "sha256": sha256(args.pre_inventory.read_bytes()),
            "payload": pre,
        },
        "post_inventory": {
            "path": str(args.post_inventory.resolve(strict=True)),
            "sha256": sha256(args.post_inventory.read_bytes()),
            "payload": post,
        },
        "mutation_monitor": {
            "path": str(args.monitor_receipt.resolve(strict=True)),
            "sha256": sha256(args.monitor_receipt.read_bytes()),
            "payload": monitor,
        },
        "dependency_pre_inventory": {
            "path": str(args.dependency_pre_inventory.resolve(strict=True)),
            "sha256": sha256(args.dependency_pre_inventory.read_bytes()),
            "payload": dependency_pre,
        },
        "dependency_post_inventory": {
            "path": str(args.dependency_post_inventory.resolve(strict=True)),
            "sha256": sha256(args.dependency_post_inventory.read_bytes()),
            "payload": dependency_post,
        },
        "dependency_mutation_monitor": {
            "path": str(args.dependency_monitor_receipt.resolve(strict=True)),
            "sha256": sha256(args.dependency_monitor_receipt.read_bytes()),
            "payload": dependency_monitor,
        },
        "binary": binary,
        "python": python_binding,
        "tools": tools,
        "libc": linked_libc_identity(args.binary),
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
    publish(args.output, canonical_bytes(payload))


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
    monitor.add_argument("--stop", type=Path, required=True)
    monitor.add_argument("--events", type=Path, required=True)
    monitor.add_argument("--receipt", type=Path, required=True)
    receipt = commands.add_parser("receipt")
    receipt.add_argument("--revision", required=True)
    receipt.add_argument("--pre-inventory", type=Path, required=True)
    receipt.add_argument("--post-inventory", type=Path, required=True)
    receipt.add_argument("--monitor-receipt", type=Path, required=True)
    receipt.add_argument("--dependency-pre-inventory", type=Path, required=True)
    receipt.add_argument("--dependency-post-inventory", type=Path, required=True)
    receipt.add_argument("--dependency-monitor-receipt", type=Path, required=True)
    receipt.add_argument("--binary", type=Path, required=True)
    receipt.add_argument("--cargo-home", type=Path, required=True)
    receipt.add_argument("--fetch-cargo-home", type=Path, required=True)
    receipt.add_argument("--target-dir", type=Path, required=True)
    receipt.add_argument("--vendor-dir", type=Path, required=True)
    receipt.add_argument("--output", type=Path, required=True)
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
