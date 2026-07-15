#!/usr/bin/env python3
"""Capture the capability-free Linux runtime identity used by the T5 census."""

from __future__ import annotations

import hashlib
import os
import platform
import stat
import subprocess
import sys
import sysconfig
from pathlib import Path

from scripts.bench import component_quotient_contract as contract
from scripts.bench import t5_linux_publication as publication


RUNTIME_ENVIRONMENT_SCHEMA = "euf-viper.component-quotient-runtime-environment.v1"
EXCLUDED_STDLIB_DIRECTORIES = frozenset(
    {"__pycache__", "site-packages", "dist-packages"}
)
EXCLUDED_STDLIB_SUFFIXES = (".pyc", ".pyo")


class RuntimeEnvironmentError(ValueError):
    """Raised when an execution environment cannot be captured exactly."""


def _sha256_file(path: Path) -> tuple[str, int]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeEnvironmentError(f"cannot open runtime file {path}: {error}") from error
    try:
        descriptor_stat = os.fstat(descriptor)
        if not stat.S_ISREG(descriptor_stat.st_mode):
            raise RuntimeEnvironmentError(f"runtime file is not regular: {path}")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
        named_after = os.stat(path, follow_symlinks=False)
        if (
            after.st_size != size
            or (after.st_dev, after.st_ino)
            != (descriptor_stat.st_dev, descriptor_stat.st_ino)
            or (named_after.st_dev, named_after.st_ino)
            != (descriptor_stat.st_dev, descriptor_stat.st_ino)
        ):
            raise RuntimeEnvironmentError(f"runtime file changed while hashed: {path}")
        return digest.hexdigest(), size
    finally:
        os.close(descriptor)


def _stdlib_tree(root: Path) -> dict[str, object]:
    try:
        canonical = root.resolve(strict=True)
    except OSError as error:
        raise RuntimeEnvironmentError(f"cannot resolve Python stdlib {root}: {error}") from error
    if not canonical.is_dir():
        raise RuntimeEnvironmentError(f"Python stdlib is not a directory: {canonical}")
    digest = hashlib.sha256()
    files = 0
    symlinks = 0
    total_bytes = 0
    for current, directories, names in os.walk(canonical, followlinks=False):
        for name in sorted(directories):
            path = Path(current) / name
            if not path.is_symlink():
                continue
            row = {
                "kind": "symlink",
                "path": path.relative_to(canonical).as_posix(),
                "target": os.readlink(path),
            }
            digest.update(contract.canonical_json_bytes(row))
            symlinks += 1
        directories[:] = sorted(
            name
            for name in directories
            if name not in EXCLUDED_STDLIB_DIRECTORIES
            and not (Path(current) / name).is_symlink()
        )
        for name in sorted(names):
            if name.endswith(EXCLUDED_STDLIB_SUFFIXES):
                continue
            path = Path(current) / name
            relative = path.relative_to(canonical).as_posix()
            path_stat = path.lstat()
            if stat.S_ISLNK(path_stat.st_mode):
                row = {
                    "kind": "symlink",
                    "path": relative,
                    "target": os.readlink(path),
                }
                symlinks += 1
            elif stat.S_ISREG(path_stat.st_mode):
                file_sha256, size = _sha256_file(path)
                row = {
                    "kind": "file",
                    "path": relative,
                    "bytes": size,
                    "mode": f"{stat.S_IMODE(path_stat.st_mode):04o}",
                    "sha256": file_sha256,
                }
                files += 1
                total_bytes += size
            else:
                raise RuntimeEnvironmentError(
                    f"Python stdlib contains an unsupported entry: {path}"
                )
            digest.update(contract.canonical_json_bytes(row))
    return {
        "path": str(canonical),
        "files": files,
        "symlinks": symlinks,
        "bytes": total_bytes,
        "tree_sha256": digest.hexdigest(),
    }


def _mapped_shared_libraries() -> list[dict[str, object]]:
    try:
        lines = Path("/proc/self/maps").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise RuntimeEnvironmentError(f"cannot read Linux shared-library maps: {error}") from error
    paths: set[Path] = set()
    for line in lines:
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or not fields[5].startswith("/"):
            continue
        mapped = fields[5]
        if mapped.endswith(" (deleted)"):
            raise RuntimeEnvironmentError(
                f"a mapped runtime library was deleted: {mapped}"
            )
        path = Path(mapped)
        if path.is_file() and (".so" in path.name or path.name.startswith("ld-")):
            paths.add(path.resolve(strict=True))
    if not paths:
        raise RuntimeEnvironmentError("Linux runtime exposes no mapped shared libraries")
    output = []
    for path in sorted(paths, key=str):
        file_sha256, size = _sha256_file(path)
        output.append({"path": str(path), "bytes": size, "sha256": file_sha256})
    return output


def _decode_mount_path(value: str) -> str:
    for escaped, decoded in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(escaped, decoded)
    return value


def _mount_binding(path: Path) -> dict[str, object]:
    try:
        canonical = path.resolve(strict=True)
        lines = Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise RuntimeEnvironmentError(f"cannot capture mount binding for {path}: {error}") from error
    selected: tuple[int, list[str], list[str]] | None = None
    canonical_text = str(canonical)
    for line in lines:
        before, separator, after = line.partition(" - ")
        if not separator:
            raise RuntimeEnvironmentError("/proc/self/mountinfo contains a malformed row")
        left = before.split()
        right = after.split()
        if len(left) < 6 or len(right) < 3:
            raise RuntimeEnvironmentError("/proc/self/mountinfo contains a short row")
        mount_point = _decode_mount_path(left[4])
        if canonical_text == mount_point or canonical_text.startswith(mount_point.rstrip("/") + "/"):
            candidate = (len(mount_point), left, right)
            if selected is None or candidate[0] > selected[0]:
                selected = candidate
    if selected is None:
        raise RuntimeEnvironmentError(f"no mountinfo row covers {canonical}")
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


def _filesystem_binding(path: Path, *, directory: bool) -> dict[str, object]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeEnvironmentError(f"cannot open filesystem binding {path}: {error}") from error
    try:
        descriptor_stat = os.fstat(descriptor)
        if directory != stat.S_ISDIR(descriptor_stat.st_mode) or (
            not directory and not stat.S_ISREG(descriptor_stat.st_mode)
        ):
            raise RuntimeEnvironmentError(
                f"filesystem binding has the wrong file type: {path}"
            )
        named_stat = os.stat(path, follow_symlinks=True)
        if (named_stat.st_dev, named_stat.st_ino) != (
            descriptor_stat.st_dev,
            descriptor_stat.st_ino,
        ):
            raise RuntimeEnvironmentError(
                f"filesystem binding path changed while opened: {path}"
            )
        statfs = publication.statfs_properties(descriptor)
        mount = _mount_binding(path)
        after = os.fstat(descriptor)
        named_after = os.stat(path, follow_symlinks=True)
        if (
            (after.st_dev, after.st_ino)
            != (descriptor_stat.st_dev, descriptor_stat.st_ino)
            or (named_after.st_dev, named_after.st_ino)
            != (descriptor_stat.st_dev, descriptor_stat.st_ino)
        ):
            raise RuntimeEnvironmentError(
                f"filesystem binding descriptor changed: {path}"
            )
    except publication.PublicationError as error:
        raise RuntimeEnvironmentError(str(error)) from error
    finally:
        os.close(descriptor)
    return {
        "path": str(Path(os.path.abspath(path))),
        "device": descriptor_stat.st_dev,
        "inode": descriptor_stat.st_ino,
        "mode": f"{stat.S_IMODE(descriptor_stat.st_mode):04o}",
        "statfs": statfs,
        "mount": mount,
    }


def _command_version(command: str) -> str:
    try:
        completed = subprocess.run(
            [command, "--version"],
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
        raise RuntimeEnvironmentError(f"cannot capture {command} version: {error}") from error
    output = completed.stdout.strip()
    if not output or "\n" in output:
        raise RuntimeEnvironmentError(f"{command} version output is malformed")
    return output


def capture_runtime_environment(
    *,
    repository_root: Path,
    manifest_path: Path,
    namespace_root: Path,
    results_path: Path,
    python_realpath: Path,
    python_version: str,
    python_sha256: str,
    slurm: dict[str, object],
) -> dict[str, object]:
    if not sys.platform.startswith("linux"):
        raise RuntimeEnvironmentError("T5 runtime inventory requires Linux")
    resolved_python = Path(sys.executable).resolve(strict=True)
    if resolved_python != python_realpath.resolve(strict=True):
        raise RuntimeEnvironmentError("runtime inventory Python realpath drift")
    executable_sha256, executable_bytes = _sha256_file(resolved_python)
    if platform.python_version() != python_version or executable_sha256 != python_sha256:
        raise RuntimeEnvironmentError("runtime inventory Python identity drift")
    stdlib_roots = []
    seen_roots: set[Path] = set()
    for key in ("stdlib", "platstdlib"):
        value = sysconfig.get_path(key)
        if not value:
            raise RuntimeEnvironmentError(f"Python sysconfig lacks {key}")
        root = Path(value).resolve(strict=True)
        if root not in seen_roots:
            seen_roots.add(root)
            stdlib_roots.append(_stdlib_tree(root))
    os_release_path = Path("/etc/os-release")
    try:
        os_release_resolved = os_release_path.resolve(strict=True)
        os_release_link = (
            os.readlink(os_release_path) if os_release_path.is_symlink() else None
        )
    except OSError as error:
        raise RuntimeEnvironmentError(f"cannot resolve /etc/os-release: {error}") from error
    os_release_sha256, os_release_bytes = _sha256_file(os_release_resolved)
    results_descriptor = os.open(
        results_path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        publication_environment = publication.capture_publication_environment(
            results_descriptor
        )
    except publication.PublicationError as error:
        raise RuntimeEnvironmentError(str(error)) from error
    finally:
        os.close(results_descriptor)
    required_slurm = {
        "sbatch_parsable",
        "job_id",
        "cluster",
        "job_name",
        "user",
        "workdir",
    }
    if set(slurm) != required_slurm:
        raise RuntimeEnvironmentError("Slurm runtime identity field set drift")
    if slurm["job_id"] != int(os.environ.get("SLURM_JOB_ID", "0")):
        raise RuntimeEnvironmentError("SLURM_JOB_ID differs from the submission binding")
    if os.environ.get("SLURM_CLUSTER_NAME") != slurm["cluster"]:
        raise RuntimeEnvironmentError("SLURM_CLUSTER_NAME differs from sbatch --parsable")
    if os.environ.get("SLURM_JOB_NAME") != slurm["job_name"]:
        raise RuntimeEnvironmentError("SLURM_JOB_NAME differs from the submission binding")
    if os.environ.get("SLURM_JOB_USER") not in {None, slurm["user"]}:
        raise RuntimeEnvironmentError("SLURM_JOB_USER differs from the submission binding")
    if os.path.realpath(os.environ.get("SLURM_SUBMIT_DIR", "")) != slurm["workdir"]:
        raise RuntimeEnvironmentError("SLURM_SUBMIT_DIR differs from the submission binding")
    uname = platform.uname()
    libc_name, libc_version = platform.libc_ver()
    return {
        "schema": RUNTIME_ENVIRONMENT_SCHEMA,
        "python": {
            "realpath": str(resolved_python),
            "version": python_version,
            "sha256": executable_sha256,
            "bytes": executable_bytes,
            "implementation": platform.python_implementation(),
            "compiler": platform.python_compiler(),
            "abi": sysconfig.get_config_var("SOABI"),
            "multiarch": sysconfig.get_config_var("MULTIARCH"),
            "stdlib": stdlib_roots,
            "mapped_shared_libraries": _mapped_shared_libraries(),
        },
        "operating_system": {
            "system": uname.system,
            "node": uname.node,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
            "libc": {"name": libc_name, "version": libc_version},
            "os_release": {
                "path": "/etc/os-release",
                "resolved_path": str(os_release_resolved),
                "symlink_target": os_release_link,
                "bytes": os_release_bytes,
                "sha256": os_release_sha256,
            },
        },
        "filesystems": {
            "repository": _filesystem_binding(repository_root, directory=True),
            "manifest": _filesystem_binding(manifest_path, directory=False),
            "namespace": _filesystem_binding(namespace_root, directory=True),
            "results": _filesystem_binding(results_path, directory=True),
        },
        "publication": publication_environment,
        "slurm": {
            **slurm,
            "scontrol_version": _command_version("scontrol"),
            "sacct_version": _command_version("sacct"),
        },
    }


def validate_runtime_environment(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != {
        "schema",
        "python",
        "operating_system",
        "filesystems",
        "publication",
        "slurm",
    }:
        raise RuntimeEnvironmentError("runtime environment field set drift")
    if value["schema"] != RUNTIME_ENVIRONMENT_SCHEMA:
        raise RuntimeEnvironmentError("runtime environment schema drift")
    python = value["python"]
    if type(python) is not dict or set(python) != {
        "realpath",
        "version",
        "sha256",
        "bytes",
        "implementation",
        "compiler",
        "abi",
        "multiarch",
        "stdlib",
        "mapped_shared_libraries",
    }:
        raise RuntimeEnvironmentError("runtime Python field set drift")
    if (
        type(python["realpath"]) is not str
        or not python["realpath"].startswith("/")
        or type(python["version"]) is not str
        or not python["version"]
        or type(python["sha256"]) is not str
        or type(python["bytes"]) is not int
        or python["bytes"] < 1
        or type(python["implementation"]) is not str
        or not python["implementation"]
        or type(python["compiler"]) is not str
        or not python["compiler"]
        or python["abi"] is not None
        and type(python["abi"]) is not str
        or python["multiarch"] is not None
        and type(python["multiarch"]) is not str
    ):
        raise RuntimeEnvironmentError("runtime Python identity is malformed")
    try:
        contract.require_lower_sha256(python["sha256"], "runtime Python digest")
    except contract.ContractError as error:
        raise RuntimeEnvironmentError(str(error)) from error
    stdlib = python["stdlib"]
    if type(stdlib) is not list or not stdlib:
        raise RuntimeEnvironmentError("runtime Python stdlib inventory is empty")
    seen_stdlib: set[str] = set()
    for row in stdlib:
        if type(row) is not dict or set(row) != {
            "path",
            "files",
            "symlinks",
            "bytes",
            "tree_sha256",
        }:
            raise RuntimeEnvironmentError("runtime stdlib record field set drift")
        path = row["path"]
        if type(path) is not str or not path.startswith("/") or path in seen_stdlib:
            raise RuntimeEnvironmentError("runtime stdlib path is malformed or duplicated")
        seen_stdlib.add(path)
        if any(
            type(row[field]) is not int or row[field] < 0
            for field in ("files", "symlinks", "bytes")
        ) or row["files"] < 1 or type(row["tree_sha256"]) is not str:
            raise RuntimeEnvironmentError("runtime stdlib counters are malformed")
        try:
            contract.require_lower_sha256(
                row["tree_sha256"], "runtime stdlib tree digest"
            )
        except contract.ContractError as error:
            raise RuntimeEnvironmentError(str(error)) from error
    libraries = python["mapped_shared_libraries"]
    if type(libraries) is not list or not libraries:
        raise RuntimeEnvironmentError("runtime mapped shared-library inventory is empty")
    library_paths: list[str] = []
    for row in libraries:
        if type(row) is not dict or set(row) != {"path", "bytes", "sha256"}:
            raise RuntimeEnvironmentError("runtime shared-library record field set drift")
        path = row["path"]
        if (
            type(path) is not str
            or not path.startswith("/")
            or type(row["bytes"]) is not int
            or row["bytes"] < 1
            or type(row["sha256"]) is not str
        ):
            raise RuntimeEnvironmentError("runtime shared-library identity is malformed")
        try:
            contract.require_lower_sha256(
                row["sha256"], "runtime shared-library digest"
            )
        except contract.ContractError as error:
            raise RuntimeEnvironmentError(str(error)) from error
        library_paths.append(path)
    if library_paths != sorted(set(library_paths)):
        raise RuntimeEnvironmentError("runtime shared-library paths are not unique and sorted")

    operating_system = value["operating_system"]
    if type(operating_system) is not dict or set(operating_system) != {
        "system",
        "node",
        "release",
        "version",
        "machine",
        "libc",
        "os_release",
    }:
        raise RuntimeEnvironmentError("runtime operating-system field set drift")
    if any(
        type(operating_system[field]) is not str or not operating_system[field]
        for field in ("system", "node", "release", "version", "machine")
    ) or operating_system["system"] != "Linux":
        raise RuntimeEnvironmentError("runtime kernel identity is malformed")
    libc = operating_system["libc"]
    if (
        type(libc) is not dict
        or set(libc) != {"name", "version"}
        or any(type(libc[field]) is not str or not libc[field] for field in libc)
    ):
        raise RuntimeEnvironmentError("runtime libc identity is malformed")
    os_release = operating_system["os_release"]
    if (
        type(os_release) is not dict
        or set(os_release)
        != {"path", "resolved_path", "symlink_target", "bytes", "sha256"}
        or os_release["path"] != "/etc/os-release"
        or type(os_release["resolved_path"]) is not str
        or not os_release["resolved_path"].startswith("/")
        or os_release["symlink_target"] is not None
        and type(os_release["symlink_target"]) is not str
        or type(os_release["bytes"]) is not int
        or os_release["bytes"] < 1
        or type(os_release["sha256"]) is not str
    ):
        raise RuntimeEnvironmentError("runtime os-release identity is malformed")
    try:
        contract.require_lower_sha256(
            os_release["sha256"], "runtime os-release digest"
        )
    except contract.ContractError as error:
        raise RuntimeEnvironmentError(str(error)) from error

    filesystems = value["filesystems"]
    if type(filesystems) is not dict or set(filesystems) != {
        "repository",
        "manifest",
        "namespace",
        "results",
    }:
        raise RuntimeEnvironmentError("runtime filesystem binding set drift")
    for binding in filesystems.values():
        if type(binding) is not dict or set(binding) != {
            "path",
            "device",
            "inode",
            "mode",
            "statfs",
            "mount",
        }:
            raise RuntimeEnvironmentError("runtime filesystem record field set drift")
        if (
            type(binding["path"]) is not str
            or not binding["path"].startswith("/")
            or type(binding["device"]) is not int
            or binding["device"] < 0
            or type(binding["inode"]) is not int
            or binding["inode"] < 1
            or type(binding["mode"]) is not str
            or len(binding["mode"]) != 4
        ):
            raise RuntimeEnvironmentError("runtime filesystem inode binding is malformed")
        statfs = binding["statfs"]
        if type(statfs) is not dict or set(statfs) != {
            "type",
            "block_size",
            "name_length",
            "fragment_size",
            "flags",
        } or any(type(item) is not int for item in statfs.values()):
            raise RuntimeEnvironmentError("runtime statfs binding is malformed")
        mount = binding["mount"]
        if type(mount) is not dict or set(mount) != {
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
            raise RuntimeEnvironmentError("runtime mount binding field set drift")
        if (
            mount["canonical_path"] != str(Path(binding["path"]).resolve(strict=False))
            or any(
                type(mount[field]) is not int or mount[field] < 0
                for field in ("mount_id", "parent_mount_id")
            )
            or any(
                type(mount[field]) is not str or not mount[field]
                for field in (
                    "major_minor",
                    "root",
                    "mount_point",
                    "filesystem_type",
                    "mount_source",
                )
            )
            or any(
                type(mount[field]) is not list
                or any(type(item) is not str for item in mount[field])
                for field in ("mount_options", "optional_fields", "super_options")
            )
        ):
            raise RuntimeEnvironmentError("runtime mount binding is malformed")

    publication_value = value["publication"]
    if type(publication_value) is not dict or set(publication_value) != {
        "method",
        "proc_self_fd",
        "procfs",
        "descriptor_symlink_verified",
        "capabilities",
    } or (
        publication_value["method"] != "proc_self_fd_linkat_at_symlink_follow"
        or publication_value["proc_self_fd"] != publication.PROC_SELF_FD
        or publication_value["descriptor_symlink_verified"] is not True
    ):
        raise RuntimeEnvironmentError("runtime publication environment is not capability-free procfs")
    procfs = publication_value["procfs"]
    if (
        type(procfs) is not dict
        or set(procfs) != {
            "type",
            "block_size",
            "name_length",
            "fragment_size",
            "flags",
        }
        or procfs.get("type") != publication.PROC_SUPER_MAGIC
        or any(type(item) is not int for item in procfs.values())
    ):
        raise RuntimeEnvironmentError("runtime procfs identity is malformed")
    capabilities = publication_value.get("capabilities")
    try:
        publication.validate_linux_capability_inventory(capabilities)
    except publication.PublicationError as error:
        raise RuntimeEnvironmentError(str(error)) from error

    slurm = value["slurm"]
    if type(slurm) is not dict or set(slurm) != {
        "sbatch_parsable",
        "job_id",
        "cluster",
        "job_name",
        "user",
        "workdir",
        "scontrol_version",
        "sacct_version",
    }:
        raise RuntimeEnvironmentError("runtime Slurm field set drift")
    if type(slurm["job_id"]) is not int or slurm["job_id"] < 1:
        raise RuntimeEnvironmentError("runtime Slurm job id is malformed")
    for field in (
        "sbatch_parsable",
        "cluster",
        "job_name",
        "user",
        "workdir",
        "scontrol_version",
        "sacct_version",
    ):
        if type(slurm[field]) is not str or not slurm[field]:
            raise RuntimeEnvironmentError("runtime Slurm string identity is malformed")
    try:
        contract.require_safe_token(slurm["cluster"], "runtime Slurm cluster")
        contract.require_safe_token(slurm["job_name"], "runtime Slurm job name")
        contract.require_safe_token(slurm["user"], "runtime Slurm user")
    except contract.ContractError as error:
        raise RuntimeEnvironmentError(str(error)) from error
    if (
        slurm["sbatch_parsable"] != f"{slurm['job_id']};{slurm['cluster']}"
        or not slurm["workdir"].startswith("/")
    ):
        raise RuntimeEnvironmentError("runtime Slurm submission binding drift")
    return value
