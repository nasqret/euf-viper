#!/usr/bin/env python3
"""Emit and validate a tiny non-corpus WMI environment canary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import t5_linux_publication as publication  # noqa: E402


CANARY_SCHEMA = "euf-viper.t5-wmi-environment-canary.v1"
EMISSION_SCHEMA = "euf-viper.t5-wmi-environment-canary-emission.v1"
VALIDATION_SCHEMA = "euf-viper.t5-wmi-environment-canary-validation.v1"
SACCT_FORMAT = (
    "JobIDRaw%64,SLUID%256,Cluster%128,Submit%32,JobName%128,User%128,"
    "WorkDir%4096,State%64,ExitCode%32"
)


class CanaryError(ValueError):
    """The WMI environment does not satisfy the canary contract."""


@dataclass(frozen=True)
class RootSchedulerRow:
    job_id: int
    sluid: str
    cluster: str
    submit_time: str
    job_name: str
    user: str
    workdir: str
    state: str
    exit_code: str

    def to_json(self) -> dict[str, object]:
        return {
            "source": "sacct-root-allocation",
            "job_id": self.job_id,
            "sluid": self.sluid,
            "cluster": self.cluster,
            "submit_time": self.submit_time,
            "job_name": self.job_name,
            "user": self.user,
            "workdir": self.workdir,
            "state": self.state,
            "exit_code": self.exit_code,
            "successful": self.state == "COMPLETED" and self.exit_code == "0:0",
        }


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def _sha256_file(path: Path) -> tuple[str, int]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        descriptor_stat = os.fstat(descriptor)
        if not stat.S_ISREG(descriptor_stat.st_mode):
            raise CanaryError(f"runtime path is not a regular file: {path}")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
        terminal = os.fstat(descriptor)
        if (
            (terminal.st_dev, terminal.st_ino)
            != (descriptor_stat.st_dev, descriptor_stat.st_ino)
            or terminal.st_size != size
        ):
            raise CanaryError(f"runtime path changed while hashed: {path}")
        return digest.hexdigest(), size
    finally:
        os.close(descriptor)


def _decode_mount_path(value: str) -> str:
    for escaped, decoded in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        value = value.replace(escaped, decoded)
    return value


def _mount_binding(path: Path) -> dict[str, object]:
    canonical = path.resolve(strict=True)
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise CanaryError(f"cannot read Linux mountinfo: {error}") from error
    selected: tuple[int, list[str], list[str]] | None = None
    canonical_text = str(canonical)
    for line in lines:
        before, separator, after = line.partition(" - ")
        left = before.split()
        right = after.split()
        if not separator or len(left) < 6 or len(right) < 3:
            raise CanaryError("Linux mountinfo contains a malformed row")
        mount_point = _decode_mount_path(left[4])
        if canonical_text == mount_point or canonical_text.startswith(mount_point.rstrip("/") + "/"):
            candidate = (len(mount_point), left, right)
            if selected is None or candidate[0] > selected[0]:
                selected = candidate
    if selected is None:
        raise CanaryError(f"no Linux mount covers {canonical}")
    _, left, right = selected
    return {
        "canonical_path": canonical_text,
        "mount_id": int(left[0]),
        "parent_mount_id": int(left[1]),
        "major_minor": left[2],
        "root": _decode_mount_path(left[3]),
        "mount_point": _decode_mount_path(left[4]),
        "mount_options": left[5].split(","),
        "optional_fields": left[6:],
        "filesystem_type": right[0],
        "mount_source": _decode_mount_path(right[1]),
        "super_options": right[2].split(","),
    }


def _filesystem_binding(path: Path) -> dict[str, object]:
    canonical = path.resolve(strict=True)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(canonical, flags)
    try:
        descriptor_stat = os.fstat(descriptor)
        named_stat = os.stat(canonical, follow_symlinks=False)
        if (
            not stat.S_ISDIR(descriptor_stat.st_mode)
            or (descriptor_stat.st_dev, descriptor_stat.st_ino)
            != (named_stat.st_dev, named_stat.st_ino)
        ):
            raise CanaryError(f"filesystem directory identity drift: {canonical}")
        statfs = publication.statfs_properties(descriptor)
    finally:
        os.close(descriptor)
    return {
        "path": str(canonical),
        "device": descriptor_stat.st_dev,
        "inode": descriptor_stat.st_ino,
        "mode": f"{stat.S_IMODE(descriptor_stat.st_mode):04o}",
        "statfs": statfs,
        "mount": _mount_binding(canonical),
    }


def _regular_file_identity(path: Path) -> dict[str, object]:
    canonical = path.resolve(strict=True)
    digest, size = _sha256_file(canonical)
    file_stat = canonical.stat()
    return {
        "realpath": str(canonical),
        "device": file_stat.st_dev,
        "inode": file_stat.st_ino,
        "mode": f"{stat.S_IMODE(file_stat.st_mode):04o}",
        "bytes": size,
        "sha256": digest,
    }


def _command_identity(command: str) -> dict[str, object]:
    selected = shutil.which(command, path="/usr/bin:/bin")
    if selected is None:
        raise CanaryError(f"required WMI command is unavailable: {command}")
    identity = _regular_file_identity(Path(selected))
    try:
        completed = subprocess.run(
            [identity["realpath"], "--version"],
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
            },
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise CanaryError(f"cannot execute {command} --version: {error}") from error
    version = completed.stdout.strip()
    if not version or "\n" in version:
        raise CanaryError(f"{command} version output is malformed")
    return {**identity, "available": True, "version": version}


def _python_identity() -> dict[str, object]:
    executable = Path(sys.executable).resolve(strict=True)
    identity = _regular_file_identity(executable)
    return {
        **identity,
        "version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "compiler": platform.python_compiler(),
        "abi": sysconfig.get_config_var("SOABI"),
        "multiarch": sysconfig.get_config_var("MULTIARCH"),
    }


def _job_identity() -> dict[str, object]:
    raw_job_id = os.environ.get("SLURM_JOB_ID", "")
    cluster = os.environ.get("SLURM_CLUSTER_NAME", "")
    job_name = os.environ.get("SLURM_JOB_NAME", "")
    user = os.environ.get("SLURM_JOB_USER", "")
    workdir = os.path.realpath(os.environ.get("SLURM_SUBMIT_DIR", ""))
    if (
        not raw_job_id.isdecimal()
        or int(raw_job_id) < 1
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", cluster)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", job_name)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", user)
        or not workdir.startswith("/")
    ):
        raise CanaryError("runtime Slurm identity is malformed")
    job_id = int(raw_job_id)
    return {
        "sbatch_parsable": f"{job_id};{cluster}",
        "job_id": job_id,
        "cluster": cluster,
        "job_name": job_name,
        "user": user,
        "workdir": workdir,
    }


def _git_revision(repository_root: Path) -> str:
    try:
        revision = subprocess.run(
            ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null",
            },
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise CanaryError(f"cannot bind canary Git revision: {error}") from error
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise CanaryError("canary Git revision is malformed")
    return revision


def _artifact(name: str, published: publication.PublishedFile) -> dict[str, object]:
    return {
        "name": name,
        "device": published.stat.st_dev,
        "inode": published.stat.st_ino,
        "mode": f"{stat.S_IMODE(published.stat.st_mode):04o}",
        "links": published.stat.st_nlink,
        "bytes": published.stat.st_size,
        "sha256": published.sha256,
    }


def emit_canary(
    *, repository_root: Path, output_directory: Path, expected_revision: str
) -> tuple[dict[str, object], dict[str, object]]:
    if not sys.platform.startswith("linux"):
        raise CanaryError("WMI environment canary requires Linux")
    repository_root = repository_root.resolve(strict=True)
    output_directory = output_directory.resolve(strict=True)
    job = _job_identity()
    revision = _git_revision(repository_root)
    if revision != expected_revision:
        raise CanaryError("canary checkout revision differs from submission")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    output_descriptor = os.open(output_directory, directory_flags)
    try:
        procfs = publication.capture_publication_environment(output_descriptor)
        probe_value = {
            "schema": "euf-viper.t5-wmi-environment-canary-probe.v1",
            "job": job,
            "revision": revision,
        }
        probe_payload = canonical_json_bytes(probe_value)
        probe_name = f"t5-environment-canary-probe-{job['job_id']}.json"
        probe_published = publication.publish_bytes_no_replace(
            directory_descriptor=output_descriptor,
            name=probe_name,
            payload=probe_payload,
            hook_prefix="environment_canary_probe",
        )
        probe = _artifact(probe_name, probe_published)
        uname = platform.uname()
        libc_name, libc_version = platform.libc_ver()
        value = {
            "schema": CANARY_SCHEMA,
            "status": "environment_canary_non_evidence",
            "decisive": False,
            "authoritative": False,
            "scope": "non_corpus_wmi_environment",
            "repository_revision": revision,
            "job": job,
            "python": _python_identity(),
            "runtime": {
                "system": uname.system,
                "node": uname.node,
                "release": uname.release,
                "version": uname.version,
                "machine": uname.machine,
                "libc": {"name": libc_name, "version": libc_version},
            },
            "commands": {
                "scontrol": _command_identity("scontrol"),
                "sacct": _command_identity("sacct"),
            },
            "filesystems": {
                "repository": _filesystem_binding(repository_root),
                "output": _filesystem_binding(output_directory),
            },
            "procfs_fd": procfs,
            "o_tmpfile_probe": probe,
        }
        validate_canary(value)
        payload = canonical_json_bytes(value)
        canary_name = f"t5-environment-canary-{job['job_id']}.json"
        canary_published = publication.publish_bytes_no_replace(
            directory_descriptor=output_descriptor,
            name=canary_name,
            payload=payload,
            hook_prefix="environment_canary",
        )
        canary_artifact = _artifact(canary_name, canary_published)
    finally:
        os.close(output_descriptor)
    emission = {
        "schema": EMISSION_SCHEMA,
        "status": "environment_canary_emitted_non_evidence",
        "decisive": False,
        "authoritative": False,
        "job": job,
        "canary": canary_artifact,
        "o_tmpfile_probe": probe,
    }
    return value, validate_emission(emission)


def _validate_digest(value: object, context: str) -> str:
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise CanaryError(f"{context} SHA-256 is malformed")
    return value


def _validate_artifact_record(value: object, context: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != {
        "name",
        "device",
        "inode",
        "mode",
        "links",
        "bytes",
        "sha256",
    }:
        raise CanaryError(f"{context} artifact field set drift")
    if (
        type(value["name"]) is not str
        or not value["name"]
        or "/" in value["name"]
        or type(value["device"]) is not int
        or value["device"] < 0
        or type(value["inode"]) is not int
        or value["inode"] < 1
        or value["mode"] != "0444"
        or value["links"] != 1
        or type(value["bytes"]) is not int
        or value["bytes"] < 1
    ):
        raise CanaryError(f"{context} artifact identity is malformed")
    _validate_digest(value["sha256"], context)
    return value


def _validate_job_identity(value: object, context: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != {
        "sbatch_parsable",
        "job_id",
        "cluster",
        "job_name",
        "user",
        "workdir",
    }:
        raise CanaryError(f"{context} job field set drift")
    if (
        type(value["job_id"]) is not int
        or value["job_id"] < 1
        or value["sbatch_parsable"]
        != f"{value['job_id']};{value['cluster']}"
        or type(value["workdir"]) is not str
        or not value["workdir"].startswith("/")
        or any(
            type(value[field]) is not str
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", value[field])
            for field in ("cluster", "job_name", "user")
        )
    ):
        raise CanaryError(f"{context} job identity drift")
    return value


def validate_emission(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != {
        "schema",
        "status",
        "decisive",
        "authoritative",
        "job",
        "canary",
        "o_tmpfile_probe",
    }:
        raise CanaryError("canary emission field set drift")
    if (
        value["schema"] != EMISSION_SCHEMA
        or value["status"] != "environment_canary_emitted_non_evidence"
        or value["decisive"] is not False
        or value["authoritative"] is not False
        or type(value["job"]) is not dict
    ):
        raise CanaryError("canary emission status drift")
    _validate_job_identity(value["job"], "canary emission")
    _validate_artifact_record(value["canary"], "canary emission")
    _validate_artifact_record(value["o_tmpfile_probe"], "canary emission probe")
    return value


def _validate_file_identity(value: object, context: str) -> dict[str, object]:
    required = {"realpath", "device", "inode", "mode", "bytes", "sha256"}
    if type(value) is not dict or not required.issubset(value):
        raise CanaryError(f"{context} file identity is malformed")
    if (
        type(value["realpath"]) is not str
        or not value["realpath"].startswith("/")
        or type(value["device"]) is not int
        or value["device"] < 0
        or type(value["inode"]) is not int
        or value["inode"] < 1
        or type(value["mode"]) is not str
        or type(value["bytes"]) is not int
        or value["bytes"] < 1
    ):
        raise CanaryError(f"{context} file identity drift")
    _validate_digest(value["sha256"], context)
    return value


def _validate_statfs(value: object, context: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != {
        "type",
        "block_size",
        "name_length",
        "fragment_size",
        "flags",
    }:
        raise CanaryError(f"{context} statfs field set drift")
    if (
        type(value["type"]) is not int
        or value["type"] == 0
        or any(
            type(value[field]) is not int or value[field] < 1
            for field in ("block_size", "name_length", "fragment_size")
        )
        or type(value["flags"]) is not int
    ):
        raise CanaryError(f"{context} statfs identity is malformed")
    return value


def _validate_mount(value: object, context: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != {
        "canonical_path",
        "mount_id",
        "parent_mount_id",
        "major_minor",
        "root",
        "mount_point",
        "mount_options",
        "optional_fields",
        "filesystem_type",
        "mount_source",
        "super_options",
    }:
        raise CanaryError(f"{context} mount field set drift")
    if (
        any(
            type(value[field]) is not int or value[field] < 0
            for field in ("mount_id", "parent_mount_id")
        )
        or type(value["major_minor"]) is not str
        or not re.fullmatch(r"[0-9]+:[0-9]+", value["major_minor"])
        or any(
            type(value[field]) is not str or not value[field]
            for field in (
                "canonical_path",
                "root",
                "mount_point",
                "filesystem_type",
                "mount_source",
            )
        )
        or not value["canonical_path"].startswith("/")
        or not value["root"].startswith("/")
        or not value["mount_point"].startswith("/")
        or any(
            type(value[field]) is not list
            or any(type(item) is not str or not item for item in value[field])
            for field in ("mount_options", "optional_fields", "super_options")
        )
    ):
        raise CanaryError(f"{context} mount identity is malformed")
    return value


def _validate_filesystem_binding(value: object, context: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != {
        "path",
        "device",
        "inode",
        "mode",
        "statfs",
        "mount",
    }:
        raise CanaryError(f"{context} filesystem field set drift")
    if (
        type(value["path"]) is not str
        or not value["path"].startswith("/")
        or type(value["device"]) is not int
        or value["device"] < 0
        or type(value["inode"]) is not int
        or value["inode"] < 1
        or type(value["mode"]) is not str
        or not re.fullmatch(r"[0-7]{4}", value["mode"])
    ):
        raise CanaryError(f"{context} filesystem identity is malformed")
    _validate_statfs(value["statfs"], context)
    mount = _validate_mount(value["mount"], context)
    if mount["canonical_path"] != value["path"]:
        raise CanaryError(f"{context} mount path differs from filesystem path")
    return value


def validate_canary(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != {
        "schema",
        "status",
        "decisive",
        "authoritative",
        "scope",
        "repository_revision",
        "job",
        "python",
        "runtime",
        "commands",
        "filesystems",
        "procfs_fd",
        "o_tmpfile_probe",
    }:
        raise CanaryError("environment canary field set drift")
    if (
        value["schema"] != CANARY_SCHEMA
        or value["status"] != "environment_canary_non_evidence"
        or value["decisive"] is not False
        or value["authoritative"] is not False
        or value["scope"] != "non_corpus_wmi_environment"
        or not isinstance(value["repository_revision"], str)
        or not re.fullmatch(r"[0-9a-f]{40}", value["repository_revision"])
    ):
        raise CanaryError("environment canary status drift")
    _validate_job_identity(value["job"], "environment canary")
    python = value["python"]
    if type(python) is not dict or set(python) != {
        "realpath",
        "device",
        "inode",
        "mode",
        "bytes",
        "sha256",
        "version",
        "implementation",
        "compiler",
        "abi",
        "multiarch",
    }:
        raise CanaryError("environment canary Python field set drift")
    _validate_file_identity(python, "Python")
    if any(
        type(python[field]) is not str or not python[field]
        for field in ("version", "implementation", "compiler")
    ) or any(
        python[field] is not None and type(python[field]) is not str
        for field in ("abi", "multiarch")
    ):
        raise CanaryError("environment canary Python runtime drift")
    runtime = value["runtime"]
    if (
        type(runtime) is not dict
        or set(runtime)
        != {"system", "node", "release", "version", "machine", "libc"}
        or runtime.get("system") != "Linux"
        or any(
            type(runtime[field]) is not str or not runtime[field]
            for field in ("node", "release", "version", "machine")
        )
        or type(runtime["libc"]) is not dict
        or set(runtime["libc"]) != {"name", "version"}
        or any(
            type(runtime["libc"][field]) is not str
            or not runtime["libc"][field]
            for field in ("name", "version")
        )
    ):
        raise CanaryError("environment canary Linux runtime drift")
    commands = value["commands"]
    if type(commands) is not dict or set(commands) != {"scontrol", "sacct"}:
        raise CanaryError("environment canary command set drift")
    for name, command in commands.items():
        if type(command) is not dict or set(command) != {
            "realpath",
            "device",
            "inode",
            "mode",
            "bytes",
            "sha256",
            "available",
            "version",
        }:
            raise CanaryError(f"{name} identity field set drift")
        _validate_file_identity(command, name)
        if command["available"] is not True or type(command["version"]) is not str or not command["version"]:
            raise CanaryError(f"{name} availability drift")
    filesystems = value["filesystems"]
    if type(filesystems) is not dict or set(filesystems) != {"repository", "output"}:
        raise CanaryError("environment canary filesystem set drift")
    for name, binding in filesystems.items():
        _validate_filesystem_binding(binding, f"environment canary {name}")
    procfs = value["procfs_fd"]
    if type(procfs) is not dict or set(procfs) != {
        "method",
        "proc_self_fd",
        "procfs",
        "descriptor_symlink_verified",
        "capabilities",
    } or type(procfs.get("procfs")) is not dict or (
        procfs["method"] != "proc_self_fd_linkat_at_symlink_follow"
        or procfs["proc_self_fd"] != publication.PROC_SELF_FD
        or procfs["descriptor_symlink_verified"] is not True
        or procfs["procfs"].get("type") != publication.PROC_SUPER_MAGIC
    ):
        raise CanaryError("environment canary procfs/fd semantics drift")
    _validate_statfs(procfs["procfs"], "environment canary procfs")
    try:
        publication.validate_linux_capability_inventory(procfs["capabilities"])
    except publication.PublicationError as error:
        raise CanaryError(str(error)) from error
    _validate_artifact_record(value["o_tmpfile_probe"], "O_TMPFILE probe")
    return value


def _verify_artifact(directory: Path, expected: dict[str, object]) -> bytes:
    path = directory / str(expected["name"])
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        descriptor_stat = os.fstat(descriptor)
        named_stat = os.stat(path, follow_symlinks=False)
        payload = publication.read_fd(descriptor, maximum_bytes=int(expected["bytes"]))
        digest = publication.sha256_fd(descriptor)
        os.fsync(descriptor)
        terminal = os.fstat(descriptor)
        if (
            (descriptor_stat.st_dev, descriptor_stat.st_ino)
            != (named_stat.st_dev, named_stat.st_ino)
            or (terminal.st_dev, terminal.st_ino)
            != (descriptor_stat.st_dev, descriptor_stat.st_ino)
            or descriptor_stat.st_dev != expected["device"]
            or descriptor_stat.st_ino != expected["inode"]
            or stat.S_IMODE(descriptor_stat.st_mode) != 0o444
            or descriptor_stat.st_nlink != 1
            or descriptor_stat.st_size != expected["bytes"]
            or len(payload) != expected["bytes"]
            or digest != expected["sha256"]
        ):
            raise CanaryError(f"canary artifact identity drift: {path.name}")
        return payload
    finally:
        os.close(descriptor)


def query_root_scheduler_row(job_id: int, cluster: str) -> RootSchedulerRow:
    try:
        completed = subprocess.run(
            [
                "sacct",
                "-n",
                "-P",
                "-X",
                "--clusters",
                cluster,
                "-j",
                str(job_id),
                f"--format={SACCT_FORMAT}",
            ],
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
            },
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise CanaryError(f"cannot query canary root scheduler row: {error}") from error
    rows: list[list[str]] = []
    for line in completed.stdout.splitlines():
        fields = line.strip().split("|")
        if len(fields) == 10 and fields[-1] == "":
            fields.pop()
        if len(fields) == 9 and fields[0] == str(job_id):
            rows.append(fields[1:])
    if len(rows) != 1:
        raise CanaryError("scheduler returned no unique canary root-allocation row")
    row = RootSchedulerRow(job_id, *rows[0])
    return _validate_scheduler_row(row, job_id=job_id, cluster=cluster)


def _validate_scheduler_row(
    row: RootSchedulerRow, *, job_id: int, cluster: str
) -> RootSchedulerRow:
    if type(row) is not RootSchedulerRow or any(
        type(value) is not str
        or not value
        or len(value) > 4096
        or any(character in value for character in "\x00\r\n|")
        for value in (
            row.sluid,
            row.cluster,
            row.submit_time,
            row.job_name,
            row.user,
            row.workdir,
            row.state,
            row.exit_code,
        )
    ):
        raise CanaryError("canary root scheduler row type drift")
    if (
        row.job_id != job_id
        or row.cluster != cluster
        or row.state != "COMPLETED"
        or row.exit_code != "0:0"
        or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}", row.submit_time)
        or not row.workdir.startswith("/")
    ):
        raise CanaryError("canary root scheduler row is unsuccessful or malformed")
    return row


def validate_canary_file(
    *,
    canary_path: Path,
    sbatch_parsable: str,
    scheduler_query: Callable[[int, str], RootSchedulerRow] = query_root_scheduler_row,
) -> dict[str, object]:
    match = re.fullmatch(r"([1-9][0-9]*);([A-Za-z0-9_.-]+)", sbatch_parsable)
    if match is None:
        raise CanaryError("canary job;cluster identity is malformed")
    job_id = int(match.group(1))
    cluster = match.group(2)
    canary_path = Path(os.path.abspath(canary_path))
    directory = canary_path.parent.resolve(strict=True)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(canary_path, flags)
    try:
        canary_stat = os.fstat(descriptor)
        named_stat = os.stat(canary_path, follow_symlinks=False)
        canary_payload = publication.read_fd(descriptor, maximum_bytes=1024 * 1024)
        if (
            not stat.S_ISREG(canary_stat.st_mode)
            or (canary_stat.st_dev, canary_stat.st_ino)
            != (named_stat.st_dev, named_stat.st_ino)
            or canary_stat.st_nlink != 1
            or stat.S_IMODE(canary_stat.st_mode) != 0o444
            or canary_stat.st_size != len(canary_payload)
        ):
            raise CanaryError("canary is not one immutable mode-0444 inode")
    finally:
        os.close(descriptor)
    def reject_constant(constant: str) -> object:
        raise CanaryError(f"canary JSON contains unsupported constant {constant}")

    try:
        value = json.loads(
            canary_payload.decode("ascii"), parse_constant=reject_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanaryError(f"canary is not strict ASCII JSON: {error}") from error
    if canonical_json_bytes(value) != canary_payload:
        raise CanaryError("canary JSON is not canonical")
    validate_canary(value)
    if value["job"]["sbatch_parsable"] != sbatch_parsable:
        raise CanaryError("canary job;cluster differs from validation request")
    canary_artifact = {
        "name": canary_path.name,
        "device": canary_stat.st_dev,
        "inode": canary_stat.st_ino,
        "mode": f"{stat.S_IMODE(canary_stat.st_mode):04o}",
        "links": canary_stat.st_nlink,
        "bytes": canary_stat.st_size,
        "sha256": hashlib.sha256(canary_payload).hexdigest(),
    }
    _validate_artifact_record(canary_artifact, "canary")
    _verify_artifact(directory, canary_artifact)
    probe = value["o_tmpfile_probe"]
    _verify_artifact(directory, probe)
    scheduler = _validate_scheduler_row(
        scheduler_query(job_id, cluster), job_id=job_id, cluster=cluster
    )
    receipt = {
        "schema": VALIDATION_SCHEMA,
        "status": "environment_canary_validated_non_evidence",
        "decisive": False,
        "authoritative": False,
        "scheduler_query_performed": True,
        "submission": {"sbatch_parsable": sbatch_parsable, "job_id": job_id, "cluster": cluster},
        "scheduler": scheduler.to_json(),
        "canary": canary_artifact,
        "o_tmpfile_probe": probe,
    }
    return validate_validation_receipt(receipt)


def validate_validation_receipt(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != {
        "schema",
        "status",
        "decisive",
        "authoritative",
        "scheduler_query_performed",
        "submission",
        "scheduler",
        "canary",
        "o_tmpfile_probe",
    }:
        raise CanaryError("canary validation receipt field set drift")
    if (
        value["schema"] != VALIDATION_SCHEMA
        or value["status"] != "environment_canary_validated_non_evidence"
        or value["decisive"] is not False
        or value["authoritative"] is not False
        or value["scheduler_query_performed"] is not True
    ):
        raise CanaryError("canary validation receipt status drift")
    submission = value["submission"]
    scheduler = value["scheduler"]
    if type(submission) is not dict or set(submission) != {
        "sbatch_parsable",
        "job_id",
        "cluster",
    } or type(scheduler) is not dict or set(scheduler) != {
        "source",
        "job_id",
        "sluid",
        "cluster",
        "submit_time",
        "job_name",
        "user",
        "workdir",
        "state",
        "exit_code",
        "successful",
    }:
        raise CanaryError("canary validation scheduler field set drift")
    if (
        type(submission["job_id"]) is not int
        or submission["job_id"] < 1
        or type(submission["cluster"]) is not str
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", submission["cluster"])
        or submission["sbatch_parsable"]
        != f"{submission['job_id']};{submission['cluster']}"
        or scheduler["source"] != "sacct-root-allocation"
        or scheduler["job_id"] != submission["job_id"]
        or scheduler["cluster"] != submission["cluster"]
        or scheduler["state"] != "COMPLETED"
        or scheduler["exit_code"] != "0:0"
        or scheduler["successful"] is not True
    ):
        raise CanaryError("canary validation scheduler binding drift")
    try:
        scheduler_row = RootSchedulerRow(
            scheduler["job_id"],
            scheduler["sluid"],
            scheduler["cluster"],
            scheduler["submit_time"],
            scheduler["job_name"],
            scheduler["user"],
            scheduler["workdir"],
            scheduler["state"],
            scheduler["exit_code"],
        )
    except TypeError as error:
        raise CanaryError("canary validation scheduler row is malformed") from error
    _validate_scheduler_row(
        scheduler_row,
        job_id=submission["job_id"],
        cluster=submission["cluster"],
    )
    _validate_artifact_record(value["canary"], "validated canary")
    _validate_artifact_record(value["o_tmpfile_probe"], "validated probe")
    return value


def _write_no_replace(path: Path, payload: bytes) -> None:
    path = Path(os.path.abspath(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        publication.write_all(descriptor, payload)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        descriptor_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(descriptor_stat.st_mode)
            or descriptor_stat.st_nlink != 1
            or stat.S_IMODE(descriptor_stat.st_mode) != 0o444
            or descriptor_stat.st_size != len(payload)
            or publication.sha256_fd(descriptor)
            != hashlib.sha256(payload).hexdigest()
        ):
            raise CanaryError("canary validation receipt persistence drift")
    finally:
        os.close(descriptor)
    directory = os.open(
        path.parent,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    emit = subparsers.add_parser("emit")
    emit.add_argument("--repository-root", type=Path, required=True)
    emit.add_argument("--output-directory", type=Path, required=True)
    emit.add_argument("--expected-revision", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--canary", type=Path, required=True)
    validate.add_argument("--sbatch-parsable", required=True)
    validate.add_argument("--receipt-out", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "emit":
            _, result = emit_canary(
                repository_root=arguments.repository_root,
                output_directory=arguments.output_directory,
                expected_revision=arguments.expected_revision,
            )
        else:
            result = validate_canary_file(
                canary_path=arguments.canary,
                sbatch_parsable=arguments.sbatch_parsable,
            )
            _write_no_replace(arguments.receipt_out, canonical_json_bytes(result))
    except (OSError, CanaryError, publication.PublicationError) as error:
        print(f"T5 environment canary failed: {error}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
