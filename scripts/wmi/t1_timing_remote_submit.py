#!/usr/bin/env python3
"""Stage, release, or cancel the descriptor-bound T1 Slurm transaction."""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA = "euf-viper.typed-parser-timing-submission.v4"
PARTITION = "cpu_idle"
NODELIST = "c1n1"
SHARDS = 128
MAX_PARALLEL = 1
FREQUENCY = "high:UserSpace"
REPOSITORY_URL = "https://github.com/nasqret/euf-viper.git"
WRAPPERS = {
    "prepare": "scripts/wmi/euf_viper_t1_timing_prepare.sbatch",
    "array": "scripts/wmi/euf_viper_t1_timing_array.sbatch",
    "audit": "scripts/wmi/euf_viper_t1_timing_audit.sbatch",
}
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
JOB_ID = re.compile(r"[1-9][0-9]*")


class TransactionError(RuntimeError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_sha256(value: str, label: str) -> str:
    if HEX64.fullmatch(value) is None:
        raise TransactionError(f"{label} must be a lowercase SHA-256")
    return value


def require_job_id(value: str, label: str) -> str:
    if JOB_ID.fullmatch(value) is None:
        raise TransactionError(f"{label} must be a canonical Slurm job id")
    return value


def clean_environment(home: Path, tools: dict[str, dict[str, Any]] | None = None) -> dict[str, str]:
    environment = {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    if tools is not None:
        for name, binding in tools.items():
            prefix = f"EUF_VIPER_{name.upper()}"
            environment[prefix] = binding["path"]
            environment[f"{prefix}_SHA256"] = binding["sha256"]
            environment[f"{prefix}_VERSION"] = binding["version"]
    return environment


def run(
    arguments: list[str],
    *,
    home: Path,
    cwd: Path | None = None,
    tools: dict[str, dict[str, Any]] | None = None,
    pass_fds: tuple[int, ...] = (),
    input_bytes: bytes | None = None,
    executable: str | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        env=clean_environment(home, tools),
        pass_fds=pass_fds,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        executable=executable,
    )


def git(repo: Path, home: Path, *arguments: str) -> bytes:
    environment = clean_environment(home)
    environment.update(
        {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
    )
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *arguments],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout


def read_opened(descriptor: int, label: str) -> bytes:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise TransactionError(f"{label} is not a regular file")
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        if not chunk:
            raise TransactionError(f"{label} became short while read")
        chunks.append(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
    )
    if identity(before) != identity(after):
        raise TransactionError(f"{label} changed while read")
    return b"".join(chunks)


def git_blob_sha1(content: bytes) -> str:
    return hashlib.sha1(f"blob {len(content)}\0".encode("ascii") + content).hexdigest()


def open_revision_file(repo: Path, home: Path, revision: str, relative: str) -> tuple[int, bytes]:
    path = repo / relative
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        content = read_opened(descriptor, relative)
        expected = git(repo, home, "rev-parse", f"{revision}:{relative}").decode("ascii").strip()
        if git_blob_sha1(content) != expected:
            raise TransactionError(f"opened runtime blob differs from revision: {relative}")
        mode = git(repo, home, "ls-tree", revision, "--", relative).decode("ascii").split()[0]
        if mode != "100755" or os.fstat(descriptor).st_mode & 0o111 == 0:
            raise TransactionError(f"runtime helper is not executable in the revision: {relative}")
        return descriptor, content
    except BaseException:
        os.close(descriptor)
        raise


def executable_identity(path: Path, *, home: Path) -> dict[str, Any]:
    canonical = path.resolve(strict=True)
    if not canonical.is_file() or canonical.is_symlink() or not os.access(canonical, os.X_OK):
        raise TransactionError(f"tool is not a canonical regular executable: {canonical}")
    descriptor = os.open(canonical, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        content = read_opened(descriptor, str(canonical))
        completed = run(
            [str(canonical), "--version"],
            home=home,
            pass_fds=(descriptor,),
            executable=f"/proc/self/fd/{descriptor}",
        )
    finally:
        os.close(descriptor)
    try:
        version = completed.stdout.decode("ascii").splitlines()[0]
    except (UnicodeDecodeError, IndexError) as error:
        raise TransactionError(f"tool emitted no ASCII version: {canonical}") from error
    if not version or "\r" in version:
        raise TransactionError(f"tool version is malformed: {canonical}")
    return {
        "path": str(canonical),
        "sha256": sha256_bytes(content),
        "bytes": len(content),
        "version": version,
    }


def tool_identities(home: Path) -> dict[str, dict[str, Any]]:
    rustup = home / ".cargo/bin/rustup"
    rustup_path = rustup.resolve(strict=True)
    rustup_fd = os.open(rustup_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        read_opened(rustup_fd, "rustup")
        cargo = run(
            [str(rustup_path), "which", "cargo"],
            home=home,
            pass_fds=(rustup_fd,),
            executable=f"/proc/self/fd/{rustup_fd}",
        ).stdout.decode("ascii").strip()
        rustc = run(
            [str(rustup_path), "which", "rustc"],
            home=home,
            pass_fds=(rustup_fd,),
            executable=f"/proc/self/fd/{rustup_fd}",
        ).stdout.decode("ascii").strip()
    finally:
        os.close(rustup_fd)
    requested = {
        "ar": Path("/usr/bin/ar"),
        "cargo": Path(cargo),
        "cc": Path("/usr/bin/cc"),
        "ld": Path("/usr/bin/ld"),
        "python": Path("/usr/bin/python3"),
        "rustc": Path(rustc),
    }
    return {name: executable_identity(path, home=home) for name, path in requested.items()}


def run_bound_python(
    *,
    repo: Path,
    home: Path,
    revision: str,
    relative: str,
    python: dict[str, Any],
    arguments: list[str],
) -> None:
    script_fd, _ = open_revision_file(repo, home, revision, relative)
    python_fd = os.open(python["path"], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if sha256_bytes(read_opened(python_fd, "Python")) != python["sha256"]:
            raise TransactionError("opened Python bytes differ from the pinned identity")
        run(
            [python["path"], "-I", "-B", f"/proc/self/fd/{script_fd}", *arguments],
            home=home,
            cwd=repo,
            pass_fds=(script_fd, python_fd),
            executable=f"/proc/self/fd/{python_fd}",
        )
    finally:
        os.close(python_fd)
        os.close(script_fd)


def parse_sbatch_id(output: bytes) -> str:
    value = output.decode("ascii").strip().split(";", 1)[0]
    return require_job_id(value, "sbatch result")


def parse_scontrol(output: bytes) -> dict[str, str]:
    try:
        text = output.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise TransactionError("scontrol output is not ASCII") from error
    fields: dict[str, str] = {}
    for token in text.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key in fields:
            raise TransactionError(f"scontrol repeated field {key}")
        fields[key] = value
    return fields


def job_state(job_id: str, *, home: Path) -> dict[str, str]:
    completed = run(["/usr/bin/scontrol", "show", "job", "-o", job_id], home=home)
    fields = parse_scontrol(completed.stdout)
    if fields.get("JobId") != job_id and fields.get("ArrayJobId") != job_id:
        raise TransactionError(f"scontrol returned a different job for {job_id}")
    return fields


def held_state(
    job_id: str,
    *,
    role: str,
    remote_work: Path,
    home: Path,
    array_spec: str | None,
) -> dict[str, Any]:
    fields = job_state(job_id, home=home)
    user = getpass.getuser()
    if not fields.get("UserId", "").startswith(f"{user}("):
        raise TransactionError(f"job {job_id} is not owned by {user}")
    if fields.get("WorkDir") != str(remote_work):
        raise TransactionError(f"job {job_id} has an unexpected work directory")
    if fields.get("JobName") != f"euf-t1-{role}-pending":
        raise TransactionError(f"job {job_id} has an unexpected staged name")
    if fields.get("JobState") != "PENDING" or fields.get("Reason") != "JobHeldUser":
        raise TransactionError(f"job {job_id} was not observed under user hold")
    oversubscribe = fields.get("OverSubscribe")
    exclusive = fields.get("Exclusive")
    if not oversubscribe or not oversubscribe.isascii():
        raise TransactionError(f"job {job_id} has no exact OverSubscribe state")
    if exclusive not in {"NO", "NODE", "USER", "MCS", "TOPO"}:
        raise TransactionError(f"job {job_id} has no exact Exclusive state")
    observed_array = fields.get("ArrayTaskId")
    throttle = fields.get("ArrayTaskThrottle")
    if array_spec is None:
        if observed_array is not None or throttle is not None:
            raise TransactionError(f"non-array job {job_id} has array state")
    elif observed_array != array_spec or throttle != "1":
        raise TransactionError(f"array job {job_id} geometry or throttle drifted")
    return {
        "array_task_id": observed_array,
        "array_task_throttle": throttle,
        "job_state": fields["JobState"],
        "reason": fields["Reason"],
        "oversubscribe": oversubscribe,
        "exclusive": exclusive,
        "user": user,
        "work_dir": str(remote_work),
    }


def submit_wrapper(
    *,
    role: str,
    wrapper_fd: int,
    wrapper_arguments: list[str],
    options: list[str],
    tools: dict[str, dict[str, Any]],
    home: Path,
    remote_work: Path,
) -> str:
    command = [
        "/usr/bin/sbatch",
        "--parsable",
        "--hold",
        f"--job-name=euf-t1-{role}-pending",
        f"--chdir={remote_work}",
        f"--partition={PARTITION}",
        f"--nodelist={NODELIST}",
        "--nodes=1",
        "--ntasks=1",
        "--cpus-per-task=1",
        "--hint=nomultithread",
        "--threads-per-core=1",
        "--cpu-bind=cores",
        "--mem-bind=local",
        "--export=ALL",
        *options,
        f"/proc/self/fd/{wrapper_fd}",
        *wrapper_arguments,
    ]
    completed = run(
        command,
        home=home,
        cwd=remote_work,
        tools=tools,
        pass_fds=(wrapper_fd,),
    )
    return parse_sbatch_id(completed.stdout)


def publish(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o400,
    )
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise TransactionError("short submission receipt write")
            offset += written
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def load_receipt(path: Path, expected_sha256: str) -> tuple[dict[str, Any], bytes]:
    expected_sha256 = require_sha256(expected_sha256, "submission receipt hash")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        content = read_opened(descriptor, "submission receipt")
    finally:
        os.close(descriptor)
    if sha256_bytes(content) != expected_sha256:
        raise TransactionError("submission receipt hash mismatch")
    try:
        value = json.loads(content.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransactionError("submission receipt is not canonical ASCII JSON") from error
    if not isinstance(value, dict) or canonical_bytes(value) != content:
        raise TransactionError("submission receipt is not canonical JSON")
    if (
        value.get("schema") != SCHEMA
        or value.get("status") != "held_receipt_persisted"
        or value.get("receipt_path") != str(path)
        or value.get("promotable") is not False
    ):
        raise TransactionError("submission receipt identity is invalid")
    jobs = value.get("jobs")
    if not isinstance(jobs, dict) or set(jobs) != {"prepare", "array", "audit"}:
        raise TransactionError("submission receipt job set is invalid")
    for role in ("prepare", "array", "audit"):
        job = jobs[role]
        if job is None and role == "audit" and value.get("mode") == "canary":
            continue
        if not isinstance(job, dict) or job.get("role") != role:
            raise TransactionError(f"submission receipt {role} job is invalid")
        require_job_id(job.get("id", ""), f"{role} job id")
        require_sha256(job.get("wrapper_sha256", ""), f"{role} wrapper hash")
    return value, content


def cancel_only_owned(receipt: dict[str, Any], *, home: Path) -> None:
    remote_work = receipt["remote_worktree"]
    receipt_hash = sha256_bytes(canonical_bytes(receipt))
    for role in ("audit", "array", "prepare"):
        job = receipt["jobs"].get(role)
        if not isinstance(job, dict):
            continue
        job_id = job["id"]
        try:
            fields = job_state(job_id, home=home)
        except (subprocess.CalledProcessError, TransactionError):
            continue
        allowed_names = {
            f"euf-t1-{role}-pending",
            f"euf-t1-{role}-{receipt_hash}",
        }
        if (
            fields.get("UserId", "").startswith(f"{getpass.getuser()}(")
            and fields.get("WorkDir") == remote_work
            and fields.get("JobName") in allowed_names
        ):
            subprocess.run(
                ["/usr/bin/scancel", job_id],
                env=clean_environment(home),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )


def cancel_staged_jobs(
    jobs: list[tuple[str, str]], *, remote_work: Path, home: Path
) -> None:
    for role, job_id in reversed(jobs):
        try:
            fields = job_state(job_id, home=home)
            if (
                fields.get("UserId", "").startswith(f"{getpass.getuser()}(")
                and fields.get("WorkDir") == str(remote_work)
                and fields.get("JobName") == f"euf-t1-{role}-pending"
            ):
                subprocess.run(
                    ["/usr/bin/scancel", job_id],
                    env=clean_environment(home),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
        except BaseException:
            pass


def stage(args: argparse.Namespace) -> int:
    home = Path.home().resolve(strict=True)
    if HEX40.fullmatch(args.revision) is None:
        raise TransactionError("revision must be 40 lowercase hexadecimal digits")
    if (
        not args.published_ref.startswith("origin/")
        or args.published_branch != args.published_ref.removeprefix("origin/")
        or re.fullmatch(r"[A-Za-z0-9._/-]+", args.published_ref) is None
        or ".." in args.published_ref
    ):
        raise TransactionError("published ref or branch is unsafe")
    for label, value in (
        ("contract", args.contract_sha256),
        ("manifest", args.manifest_sha256),
        ("accepted parity receipt", args.parity_receipt_sha256),
    ):
        require_sha256(value, f"{label} SHA-256")
    if args.dependency is not None:
        require_job_id(args.dependency, "external dependency")
    tools = tool_identities(home)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_root = home / "euf-viper-t1-timing-campaigns" / (
        f"{timestamp}-{os.getpid()}-{args.revision[:12]}"
    )
    remote_work = run_root / "repo"
    logs = run_root / "logs"
    campaign_root = run_root / "artifacts"
    checkout_receipt = run_root / "checkout-receipt.json"
    submission_receipt = run_root / "submission-receipt.json"
    manifest = home / "euf-viper/benchmarks/smtlib-2025/qf_uf_manifest.jsonl"
    source_root = home / "euf-viper"
    jobs: list[tuple[str, str]] = []
    run_root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_root.mkdir(mode=0o700)
    try:
        run(["/usr/bin/git", "clone", "--quiet", REPOSITORY_URL, str(remote_work)], home=home)
        git(
            remote_work,
            home,
            "fetch",
            "--quiet",
            "origin",
            f"+refs/heads/{args.published_branch}:refs/remotes/origin/{args.published_branch}",
        )
        published = git(
            remote_work, home, "rev-parse", f"{args.published_ref}^{{commit}}"
        ).decode("ascii").strip()
        if published != args.revision:
            raise TransactionError("published branch does not resolve to the submitted revision")
        git(remote_work, home, "checkout", "--quiet", "--detach", args.revision)
        if git(remote_work, home, "rev-parse", "HEAD").decode("ascii").strip() != args.revision:
            raise TransactionError("detached checkout revision mismatch")
        logs.mkdir(mode=0o700)
        contract = remote_work / "campaigns/t1-typed-parser-timing-v1.json"
        parity = remote_work / "results/wmi/typed-parser-parity-146510/receipt.json"
        for path, expected, label in (
            (contract, args.contract_sha256, "contract"),
            (manifest, args.manifest_sha256, "manifest"),
            (parity, args.parity_receipt_sha256, "accepted parity receipt"),
        ):
            if sha256_bytes(path.read_bytes()) != expected:
                raise TransactionError(f"remote {label} hash mismatch")
        run_bound_python(
            repo=remote_work,
            home=home,
            revision=args.revision,
            relative="scripts/bench/typed_parser_timing.py",
            python=tools["python"],
            arguments=[
                "verify-corpus",
                "--manifest",
                str(manifest),
                "--source-root",
                str(source_root),
                "--contract",
                str(contract),
                "--accepted-parity-receipt",
                str(parity),
                "--expected-accepted-parity-receipt-sha256",
                args.parity_receipt_sha256,
                "--expected-contract-sha256",
                args.contract_sha256,
            ],
        )
        run_bound_python(
            repo=remote_work,
            home=home,
            revision=args.revision,
            relative="scripts/wmi/t1_timing_checkout_receipt.py",
            python=tools["python"],
            arguments=[
                "--repository",
                str(remote_work),
                "--revision",
                args.revision,
                "--published-ref",
                args.published_ref,
                "--output",
                str(checkout_receipt),
            ],
        )
        checkout_sha256 = sha256_bytes(checkout_receipt.read_bytes())
        wrapper_descriptors: dict[str, int] = {}
        wrapper_hashes: dict[str, str] = {}
        try:
            roles = ("prepare", "array") if args.mode == "canary" else (
                "prepare",
                "array",
                "audit",
            )
            for role in roles:
                descriptor, content = open_revision_file(
                    remote_work, home, args.revision, WRAPPERS[role]
                )
                wrapper_descriptors[role] = descriptor
                wrapper_hashes[role] = sha256_bytes(content)
            prepare_options = [
                f"--output={logs}/prepare-%j.out",
                f"--error={logs}/prepare-%j.err",
            ]
            if args.dependency is not None:
                prepare_options.append(f"--dependency=afterok:{args.dependency}")
            prepare_id = submit_wrapper(
                role="prepare",
                wrapper_fd=wrapper_descriptors["prepare"],
                wrapper_arguments=[
                    str(remote_work),
                    args.revision,
                    args.published_ref,
                    args.mode,
                    args.contract_sha256,
                    args.manifest_sha256,
                    checkout_sha256,
                    args.parity_receipt_sha256,
                    str(submission_receipt),
                    wrapper_hashes["prepare"],
                ],
                options=prepare_options,
                tools=tools,
                home=home,
                remote_work=remote_work,
            )
            jobs.append(("prepare", prepare_id))
            array_spec = "0-0%1" if args.mode == "canary" else "0-127%1"
            array_options = [
                f"--dependency=afterok:{prepare_id}",
                f"--array={array_spec}",
                f"--output={logs}/array-%A_%a.out",
                f"--error={logs}/array-%A_%a.err",
            ]
            if args.mode == "full":
                array_options.extend(["--exclusive", f"--cpu-freq={FREQUENCY}"])
            array_id = submit_wrapper(
                role="array",
                wrapper_fd=wrapper_descriptors["array"],
                wrapper_arguments=[
                    str(remote_work),
                    args.revision,
                    args.published_ref,
                    args.mode,
                    args.contract_sha256,
                    args.manifest_sha256,
                    checkout_sha256,
                    str(submission_receipt),
                    wrapper_hashes["array"],
                ],
                options=array_options,
                tools=tools,
                home=home,
                remote_work=remote_work,
            )
            jobs.append(("array", array_id))
            audit_id: str | None = None
            if args.mode == "full":
                audit_id = submit_wrapper(
                    role="audit",
                    wrapper_fd=wrapper_descriptors["audit"],
                    wrapper_arguments=[
                        str(remote_work),
                        args.revision,
                        args.published_ref,
                        "full",
                        args.contract_sha256,
                        args.manifest_sha256,
                        checkout_sha256,
                        str(submission_receipt),
                        wrapper_hashes["audit"],
                    ],
                    options=[
                        f"--dependency=afterok:{array_id}",
                        f"--output={logs}/audit-%j.out",
                        f"--error={logs}/audit-%j.err",
                    ],
                    tools=tools,
                    home=home,
                    remote_work=remote_work,
                )
                jobs.append(("audit", audit_id))
        finally:
            for descriptor in wrapper_descriptors.values():
                os.close(descriptor)
        prepare_state = held_state(
            prepare_id,
            role="prepare",
            remote_work=remote_work,
            home=home,
            array_spec=None,
        )
        array_state = held_state(
            array_id,
            role="array",
            remote_work=remote_work,
            home=home,
            array_spec=array_spec,
        )
        audit_state = (
            held_state(
                audit_id,
                role="audit",
                remote_work=remote_work,
                home=home,
                array_spec=None,
            )
            if audit_id is not None
            else None
        )
        if args.mode == "full" and array_state["exclusive"] != "NODE":
            raise TransactionError("full array was not observed Exclusive=NODE")
        array = (
            {"min": 0, "max": 127, "step": 1, "count": 128, "throttle": 1, "spec": "0-127%1"}
            if args.mode == "full"
            else {"min": 0, "max": 0, "step": 1, "count": 1, "throttle": 1, "spec": "0-0%1"}
        )
        receipt = {
            "accepted_parity_receipt_sha256": args.parity_receipt_sha256,
            "array": array,
            "campaign_root": str(campaign_root),
            "checkout_receipt_sha256": checkout_sha256,
            "contract_max_parallel": MAX_PARALLEL,
            "contract_sha256": args.contract_sha256,
            "dependency": args.dependency,
            "jobs": {
                "prepare": {
                    "dependencies": [] if args.dependency is None else [args.dependency],
                    "held_state": prepare_state,
                    "id": prepare_id,
                    "role": "prepare",
                    "wrapper_sha256": wrapper_hashes["prepare"],
                },
                "array": {
                    "dependencies": [prepare_id],
                    "held_state": array_state,
                    "id": array_id,
                    "role": "array",
                    "wrapper_sha256": wrapper_hashes["array"],
                },
                "audit": None
                if audit_id is None
                else {
                    "dependencies": [array_id],
                    "held_state": audit_state,
                    "id": audit_id,
                    "role": "audit",
                    "wrapper_sha256": wrapper_hashes["audit"],
                },
            },
            "manifest_sha256": args.manifest_sha256,
            "mode": args.mode,
            "nodelist": NODELIST,
            "partition": PARTITION,
            "placement": {
                "cpu_binding": "cores",
                "exclusive_requested": args.mode == "full",
                "frequency_request": FREQUENCY if args.mode == "full" else None,
                "memory_binding": "local",
                "schedule": "serial-exclusive-array.v2" if args.mode == "full" else "single-shard-canary.v2",
                "threads_per_core": 1,
                "whole_node_exclusive": args.mode == "full",
            },
            "promotable": False,
            "promotion_reasons": [
                "T1 timing evidence is permanently nonpromotable research evidence",
                *(["bounded canary is incomplete"] if args.mode == "canary" else []),
            ],
            "published_ref": args.published_ref,
            "receipt_path": str(submission_receipt),
            "remote_run": str(run_root),
            "remote_worktree": str(remote_work),
            "revision": args.revision,
            "scheduled_max_parallel": 1,
            "scheduled_shards": array["count"],
            "schema": SCHEMA,
            "shards": SHARDS,
            "status": "held_receipt_persisted",
            "tools": tools,
        }
        content = canonical_bytes(receipt)
        publish(submission_receipt, content)
        sys.stdout.buffer.write(content)
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        cancel_staged_jobs(jobs, remote_work=remote_work, home=home)
        raise


def release(args: argparse.Namespace) -> int:
    home = Path.home().resolve(strict=True)
    receipt, content = load_receipt(args.receipt, args.receipt_sha256)
    receipt_hash = sha256_bytes(content)
    try:
        for role in ("prepare", "array", "audit"):
            job = receipt["jobs"].get(role)
            if not isinstance(job, dict):
                continue
            fields = job_state(job["id"], home=home)
            held = job["held_state"]
            if (
                not fields.get("UserId", "").startswith(f"{held['user']}(")
                or fields.get("WorkDir") != held["work_dir"]
                or fields.get("JobState") != "PENDING"
                or fields.get("Reason") != "JobHeldUser"
                or fields.get("JobName") != f"euf-t1-{role}-pending"
                or fields.get("OverSubscribe") != held["oversubscribe"]
                or fields.get("Exclusive") != held["exclusive"]
                or fields.get("ArrayTaskId") != held["array_task_id"]
                or fields.get("ArrayTaskThrottle") != held["array_task_throttle"]
            ):
                raise TransactionError(f"held {role} job changed before receipt release")
        for role in ("prepare", "array", "audit"):
            job = receipt["jobs"].get(role)
            if not isinstance(job, dict):
                continue
            run(
                [
                    "/usr/bin/scontrol",
                    "update",
                    f"JobId={job['id']}",
                    f"JobName=euf-t1-{role}-{receipt_hash}",
                ],
                home=home,
            )
        for role in ("prepare", "array", "audit"):
            job = receipt["jobs"].get(role)
            if not isinstance(job, dict):
                continue
            fields = job_state(job["id"], home=home)
            if fields.get("JobName") != f"euf-t1-{role}-{receipt_hash}":
                raise TransactionError(f"{role} job name did not bind the receipt hash")
        for role in ("prepare", "array", "audit"):
            job = receipt["jobs"].get(role)
            if isinstance(job, dict):
                run(["/usr/bin/scontrol", "release", job["id"]], home=home)
    except BaseException:
        cancel_only_owned(receipt, home=home)
        raise
    sys.stdout.buffer.write(
        canonical_bytes(
            {
                "receipt_sha256": receipt_hash,
                "schema": "euf-viper.typed-parser-timing-release.v1",
                "status": "released",
            }
        )
    )
    return 0


def cancel(args: argparse.Namespace) -> int:
    home = Path.home().resolve(strict=True)
    receipt, _ = load_receipt(args.receipt, args.receipt_sha256)
    cancel_only_owned(receipt, home=home)
    return 0


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(description=__doc__)
    commands = top.add_subparsers(dest="command", required=True)
    staged = commands.add_parser("stage")
    staged.add_argument("--revision", required=True)
    staged.add_argument("--published-ref", required=True)
    staged.add_argument("--published-branch", required=True)
    staged.add_argument("--mode", choices=("canary", "full"), required=True)
    staged.add_argument("--contract-sha256", required=True)
    staged.add_argument("--manifest-sha256", required=True)
    staged.add_argument("--parity-receipt-sha256", required=True)
    staged.add_argument("--dependency")
    for name in ("release", "cancel"):
        command = commands.add_parser(name)
        command.add_argument("--receipt", type=Path, required=True)
        command.add_argument("--receipt-sha256", required=True)
    return top


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "stage":
            return stage(args)
        if args.command == "release":
            return release(args)
        if args.command == "cancel":
            return cancel(args)
        raise AssertionError(args.command)
    except (OSError, subprocess.CalledProcessError, TransactionError) as error:
        print(f"T1 remote submission transaction error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
