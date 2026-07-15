#!/usr/bin/env python3
"""Independently reconstruct a sealed-build attestation from retained bytes."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "euf-viper.sealed-build-attestation.v1"
BUILD_SCHEMA = "euf-viper.sealed-linux-build.v3"
SOURCE_SCHEMA = "euf-viper.sealed-source-snapshot.v1"
INPUTS_SCHEMA = "euf-viper.retained-build-inputs.v1"
TRACE_SCHEMA = "euf-viper.canonical-build-trace.v1"
TRACE_SET_SCHEMA = "euf-viper.canonical-build-traces.v1"
TRACE_LEADING_PID = re.compile(r"^(?:\[pid +)?([0-9]+)(?:\] +| +)")
FORBIDDEN_NETWORK = re.compile(
    r"\b(?:connect|accept|accept4|sendto|recvfrom|sendmsg|recvmsg)\("
    r"|\bsocket\((?:AF_INET|AF_INET6|AF_NETLINK|AF_PACKET)"
)
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
REQUIRED_SEALS = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AttestationError(ValueError):
    """Raised when retained build evidence cannot reconstruct its claims."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        + "\n"
    ).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AttestationError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise AttestationError(f"{label} keys differ")
    return value


def require_hash(value: Any, label: str) -> str:
    if type(value) is not str or HEX64.fullmatch(value) is None:
        raise AttestationError(f"{label} is not a SHA-256 digest")
    return value


def read_at(directory: int, name: str) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise AttestationError(f"retained artifact is not regular: {name}")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if identity(before) != identity(after) or len(raw) != after.st_size:
        raise AttestationError(f"retained artifact changed while read: {name}")
    return raw, after


def parse_canonical(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AttestationError(f"{label} is invalid JSON: {error}") from error
    if type(value) is not dict or canonical_bytes(value) != raw:
        raise AttestationError(f"{label} is not canonical JSON")
    return value


def canonical_trace(raw: bytes, workspace: str, phase: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise AttestationError(f"{phase} trace is not UTF-8") from error
    pids: dict[str, str] = {}
    lines: list[str] = []
    random_events = 0
    time_events = 0
    for raw_line in text.splitlines():
        if "strace: Process" in raw_line:
            continue
        line = raw_line
        match = TRACE_LEADING_PID.match(line)
        if match is not None:
            pid = match.group(1)
            line = pids.setdefault(pid, f"$PID{len(pids)}") + " " + line[match.end() :]
        line = line.replace(workspace, "$WORKSPACE")
        line = re.sub(r"/proc/[0-9]+", "/proc/$PID", line)
        if FORBIDDEN_NETWORK.search(line):
            raise AttestationError(f"{phase} trace contains a network syscall")
        if "getrandom(" in line or "/dev/urandom" in line or "/dev/random" in line:
            random_events += 1
        if re.search(r"\b(?:clock_gettime|clock_getres|gettimeofday|time)\(", line):
            time_events += 1
        lines.append(line)
    if not lines:
        raise AttestationError(f"{phase} trace has no syscall records")
    encoded = ("\n".join(lines) + "\n").encode()
    return {
        "canonical_lines": lines,
        "canonical_sha256": sha256(encoded),
        "channels": {
            "network": "denied",
            "randomness_events": random_events,
            "time_events": time_events,
        },
        "phase": phase,
        "raw_sha256": sha256(raw),
        "schema": TRACE_SCHEMA,
    }


def verify_source_bundle(raw: bytes, manifest: dict[str, Any]) -> dict[str, Any]:
    require_exact_keys(
        manifest, {"files", "revision", "schema", "tree"}, "source manifest"
    )
    if (
        manifest["schema"] != SOURCE_SCHEMA
        or type(manifest["files"]) is not list
        or type(manifest["revision"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", manifest["revision"]) is None
        or type(manifest["tree"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", manifest["tree"]) is None
    ):
        raise AttestationError("source manifest identity differs")
    members: dict[str, tuple[bytes, int]] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive.getmembers():
            member_path = PurePosixPath(member.name)
            if (
                not member.isfile()
                or member.name in members
                or member_path.is_absolute()
                or ".." in member_path.parts
            ):
                raise AttestationError("source snapshot contains a non-file or duplicate")
            handle = archive.extractfile(member)
            if handle is None:
                raise AttestationError("source snapshot member cannot be read")
            members[member.name] = (handle.read(), member.mode & 0o777)
    embedded = members.pop(".euf-viper-sealed-source-manifest.json", None)
    if embedded is None or embedded[1] != 0o444:
        raise AttestationError("source snapshot omitted its manifest")
    embedded_manifest = parse_canonical(embedded[0], "source snapshot manifest")
    if embedded_manifest != manifest or embedded_manifest.get("schema") != SOURCE_SCHEMA:
        raise AttestationError("source snapshot manifest differs from build manifest")
    expected_names: set[str] = set()
    for item in manifest["files"]:
        require_exact_keys(
            item,
            {"bytes", "category", "mode", "path", "sha256"},
            "source file record",
        )
        path = item["path"]
        safe_path = PurePosixPath(path) if type(path) is str else PurePosixPath("..")
        if (
            type(path) is not str
            or not path
            or safe_path.is_absolute()
            or ".." in safe_path.parts
            or path in expected_names
            or type(item["bytes"]) is not int
            or item["bytes"] < 0
            or type(item["category"]) is not str
            or not item["category"]
            or type(item["mode"]) is not str
            or not re.fullmatch(r"0[0-7]{3}", item["mode"])
        ):
            raise AttestationError("source manifest contains an unsafe file record")
        require_hash(item["sha256"], "source file digest")
        expected_names.add(path)
    if set(members) != expected_names:
        raise AttestationError("source snapshot file set differs")
    for item in manifest["files"]:
        content, mode = members[item["path"]]
        if (
            len(content) != item["bytes"]
            or sha256(content) != item["sha256"]
            or f"{mode:04o}" != item["mode"]
        ):
            raise AttestationError(f"source snapshot member differs: {item['path']}")
    return {
        "bundle_sha256": sha256(raw),
        "file_count": len(members),
        "manifest_sha256": sha256(embedded[0]),
        "revision": manifest["revision"],
        "tree": manifest["tree"],
    }


def verify_input_bundle(
    archive_raw: bytes, index_raw: bytes, expected_index: dict[str, Any]
) -> dict[str, Any]:
    index = parse_canonical(index_raw, "retained build-input index")
    require_exact_keys(index, {"files", "object_count", "schema"}, "build-input index")
    if (
        index != expected_index
        or index["schema"] != INPUTS_SCHEMA
        or type(index["files"]) is not list
        or type(index["object_count"]) is not int
        or index["object_count"] < 1
    ):
        raise AttestationError("retained build-input index differs from manifest")
    paths: set[str] = set()
    expected_objects: set[str] = set()
    object_modes: dict[str, set[int]] = {}
    for item in index["files"]:
        require_exact_keys(
            item,
            {"bytes", "category", "mode", "object", "path", "sha256"},
            "retained build-input record",
        )
        digest = require_hash(item["sha256"], "retained build-input digest")
        object_name = f"objects/{digest}"
        if (
            type(item["path"]) is not str
            or not item["path"].startswith("/")
            or item["path"] in paths
            or item["object"] != object_name
            or type(item["bytes"]) is not int
            or item["bytes"] < 1
            or type(item["category"]) is not str
            or not item["category"]
            or type(item["mode"]) is not str
            or re.fullmatch(r"0[0-7]{3}", item["mode"]) is None
        ):
            raise AttestationError("retained build-input record is malformed")
        paths.add(item["path"])
        expected_objects.add(object_name)
        object_modes.setdefault(object_name, set()).add(int(item["mode"], 8))
    objects: dict[str, bytes] = {}
    archive_modes: dict[str, int] = {}
    embedded_index: bytes | None = None
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                raise AttestationError("retained input archive contains a non-file")
            handle = archive.extractfile(member)
            if handle is None:
                raise AttestationError("retained input object cannot be read")
            content = handle.read()
            if member.name == "retained-build-inputs.json":
                embedded_index = content
            elif member.name.startswith("objects/") and member.name not in objects:
                objects[member.name] = content
                archive_modes[member.name] = member.mode & 0o777
            else:
                raise AttestationError("retained input archive contains an unexpected member")
    if embedded_index != index_raw:
        raise AttestationError("retained input archive index differs")
    cargo: list[str] = []
    rustc: list[str] = []
    for item in index["files"]:
        content = objects.get(item["object"])
        if (
            content is None
            or len(content) != item["bytes"]
            or sha256(content) != item["sha256"]
        ):
            raise AttestationError(f"retained build input differs: {item.get('path')}")
        if item["category"] == "rust_toolchain_input":
            if item["path"].endswith("/bin/cargo"):
                cargo.append(item["sha256"])
            if item["path"].endswith("/bin/rustc"):
                rustc.append(item["sha256"])
    if len(cargo) != 1 or len(rustc) != 1:
        raise AttestationError("retained inputs do not independently bind cargo and rustc")
    if set(objects) != expected_objects or index["object_count"] != len(objects):
        raise AttestationError("retained input object set differs from its index")
    for name, mode in archive_modes.items():
        if mode not in object_modes[name]:
            raise AttestationError(f"retained input object mode differs: {name}")
    return {
        "archive_sha256": sha256(archive_raw),
        "cargo_sha256": cargo[0],
        "file_count": len(index["files"]),
        "index_sha256": sha256(index_raw),
        "object_count": len(objects),
        "rustc_sha256": rustc[0],
    }


def execute_feature_bytes(content: bytes) -> list[str]:
    if not sys.platform.startswith("linux") or not hasattr(os, "memfd_create"):
        raise AttestationError("feature reconstruction requires Linux sealed memfd")
    descriptor = os.memfd_create(
        "euf-viper-attested-features", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    )
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise AttestationError("short feature-report memfd write")
            offset += written
        os.fchmod(descriptor, 0o500)
        fcntl.fcntl(descriptor, F_ADD_SEALS, REQUIRED_SEALS)
        completed = subprocess.run(
            [f"/proc/self/fd/{descriptor}"],
            capture_output=True,
            check=False,
            pass_fds=(descriptor,),
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
        )
    finally:
        os.close(descriptor)
    if completed.returncode != 0:
        raise AttestationError("retained feature-report executable failed")
    output = completed.stdout.decode("ascii", "strict").strip()
    features = output.split(",") if output else []
    if features != sorted(set(features)) or "production-evidence" not in features:
        raise AttestationError("retained feature-report output is invalid")
    return features


BASE_NAMES = {
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


def reconstruct(directory: int) -> dict[str, Any]:
    names = set(os.listdir(directory))
    permitted = BASE_NAMES | {"sealed-build-attestation.json", "sealed-build-receipt.json"}
    if not BASE_NAMES <= names or not names <= permitted:
        raise AttestationError("sealed build artifact set differs")
    files = {name: read_at(directory, name) for name in BASE_NAMES}
    manifest = parse_canonical(files["sealed-build-manifest.json"][0], "sealed build manifest")
    require_exact_keys(
        manifest,
        {
            "artifacts",
            "build_execution_closure",
            "build_execution_closure_sha256",
            "build_execution_verification",
            "revision",
            "schema",
            "source_snapshot",
            "source_snapshot_manifest_sha256",
            "source_tree",
            "status",
            "toolchain",
        },
        "sealed build manifest",
    )
    if (
        manifest["schema"] != BUILD_SCHEMA
        or manifest["status"] != "built"
        or type(manifest["artifacts"]) is not dict
        or set(manifest["artifacts"])
        != {"euf-viper", "euf-viper-build-features"}
        or type(manifest["toolchain"]) is not dict
        or set(manifest["toolchain"]) != {"cargo", "rustc"}
    ):
        raise AttestationError("sealed build manifest schema or status differs")
    artifact_records: dict[str, dict[str, Any]] = {}
    for name in ("euf-viper", "euf-viper-build-features"):
        raw, metadata = files[name]
        expected = {"bytes": len(raw), "name": name, "sha256": sha256(raw)}
        if manifest.get("artifacts", {}).get(name) != expected:
            raise AttestationError(f"binary artifact differs from manifest: {name}")
        artifact_records[name] = {
            "bytes": len(raw),
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "sha256": sha256(raw),
        }
        if artifact_records[name]["mode"] != "0500":
            raise AttestationError(f"binary artifact mode differs: {name}")
    features = execute_feature_bytes(files["euf-viper-build-features"][0])
    closure = manifest["build_execution_closure"]
    require_exact_keys(
        closure,
        {
            "access_discovery",
            "external_directories",
            "external_inputs",
            "policy",
            "python_runtime",
            "retained_inputs",
            "rust_toolchain",
            "schema",
        },
        "build execution closure",
    )
    if (
        closure["schema"] != "euf-viper.build-execution-closure.v3"
        or closure["policy"] != "two-pass-all-syscall-trace-sealed-memfd-v2"
        or sha256(canonical_bytes(closure))
        != require_hash(
            manifest["build_execution_closure_sha256"],
            "build execution closure digest",
        )
    ):
        raise AttestationError("build execution closure digest differs")
    retained = closure["retained_inputs"]
    require_exact_keys(
        retained,
        {"archive_sha256", "index", "index_sha256", "source_snapshot_sha256"},
        "retained build inputs",
    )
    source = verify_source_bundle(
        files["sealed-source-snapshot.tar"][0], manifest["source_snapshot"]
    )
    inputs = verify_input_bundle(
        files["retained-build-inputs.tar"][0],
        files["retained-build-inputs.json"][0],
        retained["index"],
    )
    traces = parse_canonical(files["canonical-build-traces.json"][0], "canonical build traces")
    require_exact_keys(
        traces,
        {"discovery", "namespace", "production", "recipe", "schema"},
        "canonical build traces",
    )
    if traces["schema"] != TRACE_SET_SCHEMA:
        raise AttestationError("canonical build trace schema differs")
    recipe = require_exact_keys(
        traces["recipe"],
        {"arguments", "environment", "features", "strace"},
        "canonical build recipe",
    )
    workspace = str(Path(recipe["environment"]["HOME"]).parent)
    discovery = canonical_trace(
        files["build-discovery.strace"][0], workspace, "discovery"
    )
    production = canonical_trace(
        files["build-production.strace"][0], workspace, "production"
    )
    if traces["discovery"] != discovery or traces["production"] != production:
        raise AttestationError("canonical build traces do not reconstruct from raw bytes")
    namespace = require_exact_keys(
        traces["namespace"], {"network", "root"}, "build namespace"
    )
    if namespace != {"network": "isolated", "root": "private-mount-namespace"}:
        raise AttestationError("build trace does not bind an isolated network namespace")
    if (
        recipe["strace"]
        != ["-f", "-qq", "-yy", "-xx", "-v", "-s65535", "trace=all"]
        or recipe["arguments"][:4]
        != ["build", "--locked", "--offline", "--release"]
        or recipe["environment"].get("CARGO_BUILD_JOBS") != "1"
        or recipe["environment"].get("RUSTFLAGS") != "-Ctarget-cpu=generic"
        or not str(recipe["environment"].get("SOURCE_DATE_EPOCH", "")).isdigit()
    ):
        raise AttestationError("build recipe does not bind the required compiler controls")
    verification = manifest["build_execution_verification"]
    require_exact_keys(
        verification,
        {
            "actual_trace_sha256",
            "canonical_trace_sha256",
            "external_directory_count",
            "external_input_count",
            "status",
            "unexpected_external_inputs",
            "virtual_paths",
        },
        "build execution verification",
    )
    if (
        verification["status"] != "accepted"
        or verification["unexpected_external_inputs"] != []
        or verification["external_directory_count"]
        != len(closure["external_directories"])
        or verification["external_input_count"] != len(closure["external_inputs"])
        or verification["actual_trace_sha256"] != production["raw_sha256"]
        or verification["canonical_trace_sha256"]
        != sha256(files["canonical-build-traces.json"][0])
        or require_hash(retained["archive_sha256"], "retained input archive digest")
        != inputs["archive_sha256"]
        or require_hash(retained["index_sha256"], "retained input index digest")
        != inputs["index_sha256"]
        or require_hash(
            retained["source_snapshot_sha256"], "retained source bundle digest"
        )
        != source["bundle_sha256"]
        or manifest["source_snapshot_manifest_sha256"]
        != source["manifest_sha256"]
    ):
        raise AttestationError("manifest retained-byte bindings differ")
    helper_raw = Path(__file__).read_bytes()
    return {
        "artifacts": artifact_records,
        "attestor_sha256": sha256(helper_raw),
        "build_inputs": inputs,
        "build_manifest_sha256": sha256(files["sealed-build-manifest.json"][0]),
        "closure_sha256": manifest["build_execution_closure_sha256"],
        "features": features,
        "schema": SCHEMA,
        "source": source,
        "status": "accepted",
        "toolchain": manifest["toolchain"],
        "traces": {
            "canonical_sha256": sha256(files["canonical-build-traces.json"][0]),
            "discovery_raw_sha256": discovery["raw_sha256"],
            "network": "denied-and-namespaced",
            "production_raw_sha256": production["raw_sha256"],
            "randomness_events": production["channels"]["randomness_events"],
            "time_events": production["channels"]["time_events"],
        },
    }


def publish_at(directory: int, name: str, content: bytes) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o400,
        dir_fd=directory,
    )
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise AttestationError("short attestation publication write")
            offset += written
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("create", "verify"))
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--artifact-dir-fd", type=int)
    args = parser.parse_args()
    directory = -1
    try:
        if (args.artifact_dir is None) == (args.artifact_dir_fd is None):
            raise AttestationError("supply exactly one artifact directory binding")
        directory = (
            os.dup(args.artifact_dir_fd)
            if args.artifact_dir_fd is not None
            else os.open(
                args.artifact_dir.resolve(strict=True),
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
        )
        reconstructed = reconstruct(directory)
        raw = canonical_bytes(reconstructed)
        if args.command == "create":
            publish_at(directory, "sealed-build-attestation.json", raw)
        else:
            actual, _ = read_at(directory, "sealed-build-attestation.json")
            if actual != raw:
                raise AttestationError("published attestation differs from reconstruction")
    except (OSError, AttestationError, KeyError, TypeError, ValueError) as error:
        print(f"sealed build attestation rejected: {error}", file=sys.stderr)
        return 2
    finally:
        if directory >= 0:
            os.close(directory)
    print(raw.decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
