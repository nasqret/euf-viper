#!/usr/bin/env python3
"""Build and attest one reproducible Linux T11 prebuilt bundle.

This command is intentionally separate from Stage 0A.  It runs before any
frozen benchmark is opened, builds the exact clean Git revision twice in fresh
target directories, requires byte-identical ELF outputs, derives the runtime
loader closure, and emits immutable inputs for ``t11_build_closure.py``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


_BUNDLE_MODULE_PATH = Path(__file__).resolve().with_name("t11_build_closure.py")
_BUNDLE_SPEC = importlib.util.spec_from_file_location(
    "t11_build_closure_for_preparation", _BUNDLE_MODULE_PATH
)
if _BUNDLE_SPEC is None or _BUNDLE_SPEC.loader is None:
    raise RuntimeError("cannot load adjacent T11 prebuilt bundle tool")
t11_build_closure = importlib.util.module_from_spec(_BUNDLE_SPEC)
sys.modules[_BUNDLE_SPEC.name] = t11_build_closure
_BUNDLE_SPEC.loader.exec_module(t11_build_closure)


SCHEMA = "euf-viper.t11-prebuilt-preparation.v2"
DEPENDENCY_SCHEMA = "euf-viper.t11-binary-dependencies.v1"
RECEIPT_SCHEMA = "euf-viper.t11-prebuilt-build-receipt.v1"
TARGET = "x86_64-unknown-linux-gnu"
LOGICAL_BUILD_COMMAND = [
    "cargo",
    "build",
    "--locked",
    "--features",
    "certificates",
    "--release",
    "--target",
    TARGET,
]
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
COPY_CHUNK_BYTES = 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_RUNTIME_FILES = 128


class PreparationError(RuntimeError):
    """A fail-closed T11 prebuilt preparation error."""


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class ElfInfo:
    elf_type: int
    interpreter: str | None
    needed: tuple[str, ...]


def _fail(message: str) -> None:
    raise PreparationError(message)


def _identity(value: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=value.st_dev,
        inode=value.st_ino,
        mode=value.st_mode,
        links=value.st_nlink,
        size=value.st_size,
        mtime_ns=value.st_mtime_ns,
        ctime_ns=value.st_ctime_ns,
    )


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def _read_stable(path: Path, label: str, limit: int | None = None) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail(f"{label} is not a regular file")
        if limit is not None and before.st_size > limit:
            _fail(f"{label} exceeds {limit} bytes")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(COPY_CHUNK_BYTES, remaining))
            if not block:
                _fail(f"short read while reading {label}")
            chunks.append(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after):
            _fail(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path, label: str) -> tuple[str, int]:
    value = _read_stable(path, label)
    return _sha256_bytes(value), len(value)


def _write_new(path: Path, value: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _fail(f"short write while publishing {path.name}")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _run(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    label: str,
    accepted: frozenset[int] = frozenset({0}),
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        _fail(f"cannot execute {label}: {error}")
    if len(completed.stdout) > MAX_TOOL_OUTPUT_BYTES or len(completed.stderr) > MAX_TOOL_OUTPUT_BYTES:
        _fail(f"{label} output exceeds its bound")
    if completed.returncode not in accepted:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        _fail(f"{label} failed with exit {completed.returncode}: {detail[:2000]}")
    return completed


def _tool_record(path: Path, version_argv: Sequence[str], label: str) -> dict[str, str]:
    canonical = Path(os.path.realpath(path))
    metadata = os.stat(canonical, follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
        _fail(f"{label} is not an executable regular file")
    digest, _ = _sha256_file(canonical, label)
    completed = _run(
        [str(canonical), *version_argv],
        cwd=Path("/"),
        env={"HOME": "/", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        label=f"{label} version",
    )
    stdout = completed.stdout.decode("utf-8", "strict").strip()
    stderr = completed.stderr.decode("utf-8", "strict").strip()
    if stdout and stderr:
        _fail(f"{label} version unexpectedly used both stdout and stderr")
    lines = (stdout or stderr).splitlines()
    if len(lines) != 1 or not lines[0]:
        _fail(f"{label} version is not one exact line")
    return {"path": str(canonical), "sha256": digest, "version": lines[0]}


def _git(source: Path, *arguments: str) -> str:
    completed = _run(
        ["/usr/bin/git", "-C", str(source), *arguments],
        cwd=Path("/"),
        env={"HOME": "/", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        label=f"git {arguments[0]}",
    )
    return completed.stdout.decode("ascii", "strict").rstrip("\n")


def _source_identity(source: Path) -> tuple[str, str]:
    if _git(source, "status", "--porcelain=v1", "--untracked-files=all"):
        _fail("source repository must be completely clean")
    commit = _git(source, "rev-parse", "--verify", "HEAD^{commit}")
    tree = _git(source, "rev-parse", "--verify", "HEAD^{tree}")
    if REVISION_RE.fullmatch(commit) is None or REVISION_RE.fullmatch(tree) is None:
        _fail("source Git identity is malformed")
    return commit, tree


def _cstring(data: bytes, offset: int, limit: int, label: str) -> str:
    if offset < 0 or offset >= limit or limit > len(data):
        _fail(f"{label} string offset is outside the ELF string table")
    end = data.find(b"\0", offset, limit)
    if end < 0:
        _fail(f"{label} string is not terminated")
    try:
        return data[offset:end].decode("ascii", "strict")
    except UnicodeDecodeError:
        _fail(f"{label} string is not ASCII")


def _parse_elf_bytes(
    data: bytes, label: str, *, require_interpreter: bool = False
) -> ElfInfo:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        _fail(f"{label} is not an ELF binary")
    if data[4:7] != b"\x02\x01\x01":
        _fail(f"{label} must be 64-bit little-endian ELF version 1")
    try:
        (
            elf_type,
            machine,
            version,
            _entry,
            phoff,
            _shoff,
            _flags,
            ehsize,
            phentsize,
            phnum,
            _shentsize,
            _shnum,
            _shstrndx,
        ) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    except struct.error as error:
        _fail(f"{label} has a truncated ELF header: {error}")
    if elf_type not in {2, 3} or machine != 62 or version != 1 or ehsize != 64:
        _fail(f"{label} is not a supported x86-64 Linux executable")
    if phentsize != 56 or phnum == 0 or phnum > 4096:
        _fail(f"{label} has an unsupported program-header table")
    if phoff > len(data) or phnum * phentsize > len(data) - phoff:
        _fail(f"{label} program-header table is truncated")

    loads: list[tuple[int, int, int]] = []
    dynamic: tuple[int, int] | None = None
    interpreter: str | None = None
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = struct.unpack_from(
            "<IIQQQQQQ", data, offset
        )
        if p_offset > len(data) or p_filesz > len(data) - p_offset:
            _fail(f"{label} program segment is outside the file")
        if p_type == 1:
            loads.append((p_vaddr, p_filesz, p_offset))
        elif p_type == 2:
            if dynamic is not None:
                _fail(f"{label} has multiple PT_DYNAMIC segments")
            dynamic = (p_offset, p_filesz)
        elif p_type == 3:
            if interpreter is not None or p_filesz < 2:
                _fail(f"{label} has a malformed PT_INTERP segment")
            raw = data[p_offset : p_offset + p_filesz]
            if raw[-1:] != b"\0" or b"\0" in raw[:-1]:
                _fail(f"{label} PT_INTERP is not one canonical string")
            try:
                interpreter = raw[:-1].decode("ascii", "strict")
            except UnicodeDecodeError:
                _fail(f"{label} PT_INTERP is not ASCII")

    if dynamic is None:
        _fail(f"{label} lacks a PT_DYNAMIC segment")
    if require_interpreter and (
        interpreter is None or not interpreter.startswith("/")
    ):
        _fail(f"{label} must be a dynamically linked executable with absolute PT_INTERP")
    if interpreter is not None and not interpreter.startswith("/"):
        _fail(f"{label} has a nonabsolute PT_INTERP")
    dyn_offset, dyn_size = dynamic
    if dyn_size % 16 != 0 or dyn_size > 16 * 1024 * 1024:
        _fail(f"{label} has a malformed PT_DYNAMIC segment")
    string_address: int | None = None
    string_size: int | None = None
    needed_offsets: list[int] = []
    terminated = False
    for offset in range(dyn_offset, dyn_offset + dyn_size, 16):
        tag, value = struct.unpack_from("<qQ", data, offset)
        if tag == 0:
            terminated = True
            break
        if tag == 1:
            needed_offsets.append(value)
        elif tag == 5:
            string_address = value
        elif tag == 10:
            string_size = value
        elif tag in {15, 29}:
            _fail(f"{label} contains forbidden RPATH/RUNPATH")
    if not terminated or string_address is None or string_size is None or string_size == 0:
        _fail(f"{label} dynamic string table is incomplete")
    string_offset: int | None = None
    for virtual, filesz, file_offset in loads:
        if virtual <= string_address < virtual + filesz:
            delta = string_address - virtual
            if string_size > filesz - delta:
                _fail(f"{label} dynamic string table crosses a file-backed segment")
            string_offset = file_offset + delta
            break
    if string_offset is None or string_offset + string_size > len(data):
        _fail(f"{label} dynamic string table is unmapped")
    needed: list[str] = []
    for value in needed_offsets:
        name = _cstring(data, string_offset + value, string_offset + string_size, label)
        if not name or "/" in name or "\0" in name or "\n" in name:
            _fail(f"{label} has an unsafe DT_NEEDED name")
        needed.append(name)
    if len(needed) != len(set(needed)):
        _fail(f"{label} repeats a DT_NEEDED entry")
    return ElfInfo(elf_type=elf_type, interpreter=interpreter, needed=tuple(needed))


def _parse_elf(
    path: Path, label: str, *, require_interpreter: bool = False
) -> ElfInfo:
    return _parse_elf_bytes(
        _read_stable(path, label), label, require_interpreter=require_interpreter
    )


def _assert_not_user_writable(path: Path, label: str) -> None:
    canonical = Path(os.path.realpath(path))
    if canonical != path:
        _fail(f"{label} path is not canonical: {path}")
    current = canonical
    while True:
        metadata = os.stat(current, follow_symlinks=False)
        if os.access(current, os.W_OK, effective_ids=True):
            _fail(f"{label} path is writable by the build user: {current}")
        if current == current.parent:
            break
        current = current.parent


def _runtime_closure(candidate: Path) -> tuple[ElfInfo, list[dict[str, str]], dict[str, str]]:
    candidate_info = _parse_elf(
        candidate, "candidate binary", require_interpreter=True
    )
    assert candidate_info.interpreter is not None
    requested_interpreter = Path(candidate_info.interpreter)
    if not requested_interpreter.is_absolute():
        _fail("candidate PT_INTERP is not absolute")
    canonical_interpreter = Path(os.path.realpath(requested_interpreter))
    _assert_not_user_writable(canonical_interpreter, "ELF interpreter")
    interpreter_info = _parse_elf(canonical_interpreter, "ELF interpreter")
    if interpreter_info.elf_type not in {2, 3}:
        _fail("ELF interpreter has an unsupported type")

    completed = _run(
        [str(canonical_interpreter), "--list", str(candidate)],
        cwd=Path("/"),
        env={"HOME": "/", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        label="dynamic-loader dependency resolution",
    )
    resolved: dict[str, Path] = {}
    for raw_line in completed.stdout.decode("utf-8", "strict").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("linux-vdso.so"):
            continue
        if "=>" in line:
            name, right = line.split("=>", 1)
            name = name.strip()
            value = right.strip()
            if value.startswith("not found"):
                _fail(f"dynamic dependency is unresolved: {name}")
            path_text = value.split(" (", 1)[0].strip()
        else:
            path_text = line.split(" (", 1)[0].strip()
            name = os.path.basename(path_text)
        if not path_text.startswith("/"):
            _fail(f"dynamic loader emitted a nonabsolute dependency: {line!r}")
        path = Path(os.path.realpath(path_text))
        previous = resolved.get(name)
        if previous is not None and previous != path:
            _fail(f"dynamic loader resolved {name!r} inconsistently")
        resolved[name] = path

    # glibc itself can declare the dynamic loader in DT_NEEDED while
    # ``ld.so --list`` prints the interpreter as a special row (or omits that
    # row entirely).  PT_INTERP is already parsed and independently bound, so
    # make both possible loader basenames explicit in the dependency map.
    for loader_name in {
        requested_interpreter.name,
        canonical_interpreter.name,
    }:
        previous = resolved.get(loader_name)
        if previous is not None and previous != canonical_interpreter:
            _fail(f"dynamic loader resolved {loader_name!r} inconsistently")
        resolved[loader_name] = canonical_interpreter

    queue = list(candidate_info.needed)
    seen_names: set[str] = set()
    runtime_paths: set[Path] = {canonical_interpreter}
    while queue:
        name = queue.pop(0)
        if name in seen_names:
            continue
        seen_names.add(name)
        dependency = resolved.get(name)
        if dependency is None:
            _fail(f"dynamic loader omitted DT_NEEDED dependency {name!r}")
        _assert_not_user_writable(dependency, f"runtime dependency {name}")
        runtime_paths.add(dependency)
        dependency_info = _parse_elf(dependency, f"runtime dependency {name}")
        for child in dependency_info.needed:
            if child not in seen_names:
                queue.append(child)

    records: list[dict[str, str]] = []
    for path in sorted(runtime_paths, key=lambda value: str(value).encode("utf-8")):
        digest, _ = _sha256_file(path, f"runtime dependency {path}")
        records.append({"path": str(path), "sha256": digest})
    if not 1 <= len(records) <= MAX_RUNTIME_FILES:
        _fail(
            f"runtime closure must contain between 1 and {MAX_RUNTIME_FILES} files"
        )
    mapping = {name: str(path) for name, path in sorted(resolved.items()) if name in seen_names}
    return candidate_info, records, mapping


def _copy_candidate(source: Path, destination: Path) -> bytes:
    value = _read_stable(source, "built candidate")
    _write_new(destination, value, 0o500)
    return value


def _build_once(
    source: Path,
    scratch: Path,
    cargo: Path,
    rustc: Path,
    cargo_home: Path,
    label: str,
) -> tuple[Path, dict[str, bytes]]:
    target_dir = scratch / label
    target_dir.mkdir(mode=0o700)
    environment = {
        "CARGO_HOME": str(cargo_home),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": str(target_dir),
        "HOME": str(scratch / "home"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "RUSTC": str(rustc),
        "SOURCE_DATE_EPOCH": "0",
        "TZ": "UTC",
    }
    Path(environment["HOME"]).mkdir(mode=0o700, exist_ok=True)
    argv = [str(cargo), *LOGICAL_BUILD_COMMAND[1:]]
    completed = _run(argv, cwd=source, env=environment, label=f"{label} Cargo build")
    candidate = target_dir / TARGET / "release" / "euf-viper"
    if not candidate.is_file() or candidate.is_symlink():
        _fail(f"{label} did not produce the expected candidate")
    return candidate, {"stderr": completed.stderr, "stdout": completed.stdout}


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        _fail("T11 prebuilt preparation requires x86-64 Linux")
    source = Path(os.path.realpath(args.source_repository))
    output = Path(os.path.abspath(args.output_directory))
    scratch_base = Path(os.path.realpath(args.scratch_base))
    cargo_home = Path(os.path.realpath(args.cargo_home))
    cargo = Path(os.path.realpath(args.cargo))
    rustc = Path(os.path.realpath(args.rustc))
    controller_python = Path(os.path.realpath(args.controller_python))
    bundle_tool = Path(os.path.realpath(args.bundle_tool))
    preparer = Path(os.path.realpath(__file__))
    if output.exists() or output.parent.resolve() != output.parent:
        _fail("output directory must be a fresh path under a canonical parent")
    commit, tree = _source_identity(source)
    if args.expected_commit and commit != args.expected_commit:
        _fail("source revision differs from --expected-commit")
    cargo_record = _tool_record(cargo, ["--version"], "cargo")
    rustc_record = _tool_record(rustc, ["--version"], "rustc")
    python_record = _tool_record(
        controller_python, ["--version"], "controller Python"
    )
    _assert_not_user_writable(controller_python, "controller Python")
    bundle_tool_sha256, _ = _sha256_file(bundle_tool, "prebuilt bundle tool")
    preparer_sha256, _ = _sha256_file(preparer, "prebuilt preparation tool")
    if bundle_tool_sha256 != _sha256_file(Path(t11_build_closure.__file__), "imported bundle tool")[0]:
        _fail("imported prebuilt bundle tool differs from --bundle-tool")

    output.mkdir(mode=0o700)
    try:
        preparer_snapshot = output / "preparer-snapshot.py"
        bundle_tool_snapshot = output / "bundle-tool-snapshot.py"
        _write_new(
            preparer_snapshot,
            _read_stable(preparer, "prebuilt preparation tool"),
            0o400,
        )
        _write_new(
            bundle_tool_snapshot,
            _read_stable(bundle_tool, "prebuilt bundle tool"),
            0o400,
        )
        with tempfile.TemporaryDirectory(prefix="t11-prebuilt-", dir=scratch_base) as temporary:
            scratch = Path(temporary)
            first, first_log = _build_once(source, scratch, cargo, rustc, cargo_home, "build-a")
            first_bytes = _read_stable(first, "first candidate build")
            first_sha256 = _sha256_bytes(first_bytes)
            first_info = _parse_elf_bytes(
                first_bytes, "first candidate build", require_interpreter=True
            )
            second, second_log = _build_once(source, scratch, cargo, rustc, cargo_home, "build-b")
            second_bytes = _read_stable(second, "second candidate build")
            second_sha256 = _sha256_bytes(second_bytes)
            if first_bytes != second_bytes:
                _fail("independent Cargo builds are not byte-identical")
            if _source_identity(source) != (commit, tree):
                _fail("source identity changed during reproducible builds")

            retained_builds: dict[str, dict[str, Any]] = {}
            for label, binary_bytes, logs in (
                ("build_a", first_bytes, first_log),
                ("build_b", second_bytes, second_log),
            ):
                binary_path = output / f"{label}-euf-viper"
                stdout_path = output / f"{label}-stdout.bin"
                stderr_path = output / f"{label}-stderr.bin"
                _write_new(binary_path, binary_bytes, 0o400)
                _write_new(stdout_path, logs["stdout"], 0o400)
                _write_new(stderr_path, logs["stderr"], 0o400)
                retained_builds[label] = {
                    "candidate": {
                        "bytes": len(binary_bytes),
                        "path": str(binary_path),
                        "sha256": _sha256_bytes(binary_bytes),
                    },
                    "stderr": {
                        "path": str(stderr_path),
                        "sha256": _sha256_bytes(logs["stderr"]),
                    },
                    "stdout": {
                        "path": str(stdout_path),
                        "sha256": _sha256_bytes(logs["stdout"]),
                    },
                }

            candidate = output / "euf-viper"
            candidate_bytes = _copy_candidate(first, candidate)
            candidate_sha256 = _sha256_bytes(candidate_bytes)
            candidate_info, runtime_files, resolution = _runtime_closure(candidate)
            if candidate_info != first_info:
                _fail("published candidate ELF metadata differs from the build output")

            inventory = {
                "candidate_sha256": candidate_sha256,
                "platform": "linux-x86_64",
                "runtime_files": runtime_files,
                "schema": DEPENDENCY_SCHEMA,
            }
            inventory_path = output / "dependency-inventory.json"
            inventory_bytes = _canonical_json(inventory)
            _write_new(inventory_path, inventory_bytes, 0o400)
            inventory_sha256 = _sha256_bytes(inventory_bytes)

            python_sha256, _ = _sha256_file(
                controller_python, "controller Python"
            )
            python_elf, python_runtime_files, python_resolution = _runtime_closure(
                controller_python
            )
            python_inventory = {
                "candidate_sha256": python_sha256,
                "platform": "linux-x86_64",
                "runtime_files": python_runtime_files,
                "schema": DEPENDENCY_SCHEMA,
            }
            python_inventory_path = output / "python-runtime-inventory.json"
            python_inventory_bytes = _canonical_json(python_inventory)
            _write_new(python_inventory_path, python_inventory_bytes, 0o400)
            python_inventory_sha256 = _sha256_bytes(python_inventory_bytes)

            cargo_toml_sha256, _ = _sha256_file(source / "Cargo.toml", "Cargo.toml")
            cargo_lock_sha256, _ = _sha256_file(source / "Cargo.lock", "Cargo.lock")
            receipt = {
                "binary_dependencies_sha256": inventory_sha256,
                "build_command": LOGICAL_BUILD_COMMAND,
                "candidate_bytes": len(candidate_bytes),
                "candidate_sha256": candidate_sha256,
                "cargo_lock_sha256": cargo_lock_sha256,
                "cargo_toml_sha256": cargo_toml_sha256,
                "features": ["certificates"],
                "profile": "release",
                "rust_target": TARGET,
                "schema": RECEIPT_SCHEMA,
                "source_commit": commit,
                "source_tree": tree,
            }
            receipt_path = output / "build-receipt.json"
            receipt_bytes = _canonical_json(receipt)
            _write_new(receipt_path, receipt_bytes, 0o400)

            bundle_path = output / "prebuilt-bundle.tar"
            closure = t11_build_closure.create_archive(
                str(bundle_path),
                {
                    "candidate-binary": str(candidate),
                    "build-receipt": str(receipt_path),
                    "dependency-inventory": str(inventory_path),
                },
                str(source),
            )
            extracted = scratch / "extracted"
            t11_build_closure.extract_archive(
                str(bundle_path), closure.archive_sha256, str(extracted)
            )
            extracted_candidate = extracted / "payload" / "candidate-binary"
            smoke_env = {"HOME": "/", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
            version = _run(
                [str(extracted_candidate), "--version"],
                cwd=scratch,
                env=smoke_env,
                label="bundled candidate version smoke",
            )
            help_result = _run(
                [str(extracted_candidate), "--help"],
                cwd=scratch,
                env=smoke_env,
                label="bundled candidate help smoke",
            )
            version_text = version.stdout.decode("ascii", "strict").strip()
            if not re.fullmatch(r"euf-viper [0-9]+\.[0-9]+\.[0-9]+", version_text):
                _fail("bundled candidate version output is malformed")
            if b"project-t11" not in help_result.stdout or b"audit-t11" not in help_result.stdout:
                _fail("bundled candidate lacks certificate-enabled T11 commands")
            python_smoke = _run(
                [
                    str(controller_python),
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    "import hashlib,json;print(hashlib.sha256(json.dumps({'ok':True},sort_keys=True).encode()).hexdigest())",
                ],
                cwd=scratch,
                env=smoke_env,
                label="controller Python isolated-runtime smoke",
            )
            python_smoke_text = python_smoke.stdout.decode("ascii", "strict").strip()
            if SHA256_RE.fullmatch(python_smoke_text) is None:
                _fail("controller Python smoke output is malformed")

            report = {
                "artifacts": {
                    "build_a_candidate": retained_builds["build_a"]["candidate"],
                    "build_a_stderr": retained_builds["build_a"]["stderr"],
                    "build_a_stdout": retained_builds["build_a"]["stdout"],
                    "build_b_candidate": retained_builds["build_b"]["candidate"],
                    "build_b_stderr": retained_builds["build_b"]["stderr"],
                    "build_b_stdout": retained_builds["build_b"]["stdout"],
                    "build_receipt": {"path": str(receipt_path), "sha256": _sha256_bytes(receipt_bytes)},
                    "candidate": {"bytes": len(candidate_bytes), "path": str(candidate), "sha256": candidate_sha256},
                    "dependency_inventory": {"path": str(inventory_path), "sha256": inventory_sha256},
                    "python_runtime_inventory": {
                        "path": str(python_inventory_path),
                        "sha256": python_inventory_sha256,
                    },
                    "prebuilt_bundle": {
                        "manifest_sha256": closure.manifest_sha256,
                        "path": str(bundle_path),
                        "sha256": closure.archive_sha256,
                    },
                },
                "build": {
                    "command": LOGICAL_BUILD_COMMAND,
                    "first": {
                        "candidate_sha256": first_sha256,
                        "stderr_sha256": _sha256_bytes(first_log["stderr"]),
                        "stdout_sha256": _sha256_bytes(first_log["stdout"]),
                    },
                    "reproducible": True,
                    "second": {
                        "candidate_sha256": second_sha256,
                        "stderr_sha256": _sha256_bytes(second_log["stderr"]),
                        "stdout_sha256": _sha256_bytes(second_log["stdout"]),
                    },
                },
                "elf": {
                    "candidate": {
                        "interpreter": candidate_info.interpreter,
                        "needed": list(candidate_info.needed),
                        "resolved": resolution,
                        "runtime_files": len(runtime_files),
                    },
                    "controller_python": {
                        "interpreter": python_elf.interpreter,
                        "needed": list(python_elf.needed),
                        "resolved": python_resolution,
                        "runtime_files": len(python_runtime_files),
                    },
                },
                "schema": SCHEMA,
                "smoke": {
                    "help_sha256": _sha256_bytes(help_result.stdout),
                    "python_sha256": _sha256_bytes(python_smoke.stdout),
                    "version": version_text,
                    "version_sha256": _sha256_bytes(version.stdout),
                },
                "source": {"commit": commit, "tree": tree},
                "status": "verified",
                "tools": {
                    "bundle_tool": {
                        "path": str(bundle_tool_snapshot),
                        "sha256": bundle_tool_sha256,
                    },
                    "cargo": cargo_record,
                    "preparer": {
                        "path": str(preparer_snapshot),
                        "sha256": preparer_sha256,
                    },
                    "python": python_record,
                    "rustc": rustc_record,
                },
            }
            report_path = output / "preparation.json"
            report_bytes = _canonical_json(report)
            _write_new(report_path, report_bytes, 0o400)
            os.chmod(output, 0o500)
            parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            return {**report, "preparation": {"path": str(report_path), "sha256": _sha256_bytes(report_bytes)}}
    except BaseException:
        os.chmod(output, 0o700)
        shutil.rmtree(output)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--expected-commit")
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--scratch-base", required=True)
    parser.add_argument("--cargo-home", required=True)
    parser.add_argument("--cargo", required=True)
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--controller-python", required=True)
    parser.add_argument("--bundle-tool", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        report = prepare(_parser().parse_args(argv))
    except (PreparationError, t11_build_closure.ClosureError, OSError, UnicodeError) as error:
        print(f"T11 prebuilt preparation rejected: {error}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(_canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
