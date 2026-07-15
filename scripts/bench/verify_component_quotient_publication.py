#!/usr/bin/env python3
"""Consume a T5 publication only after scheduler and fresh descriptor checks."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import secrets
import stat
import subprocess
import sys
import tarfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import component_quotient_contract as contract  # noqa: E402
from scripts.bench import independent_component_quotient_verifier as independent  # noqa: E402
from scripts.bench import t5_linux_publication as publication  # noqa: E402
from scripts.bench import t5_runtime_environment as runtime_environment  # noqa: E402


class ConsumerVerificationError(ValueError):
    """A publication lacks enough fresh evidence to authorize T5."""


MAX_ARCHIVE_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 48 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = contract.EXPECTED_SOURCES + len(contract.RUNTIME_PROJECT_FILES) + 32
SACCT_FORMAT = (
    "JobIDRaw%64,SLUID%256,Cluster%128,Submit%32,JobName%128,User%128,"
    "WorkDir%4096,State%64,ExitCode%32"
)


@dataclass(frozen=True)
class SchedulerEvidence:
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


def _safe_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }


def _require_scheduler_evidence(
    evidence: SchedulerEvidence, *, job_id: int, cluster: str
) -> SchedulerEvidence:
    if type(evidence) is not SchedulerEvidence or type(evidence.job_id) is not int:
        raise ConsumerVerificationError("scheduler evidence type drift")
    strings = (
        evidence.sluid,
        evidence.cluster,
        evidence.submit_time,
        evidence.job_name,
        evidence.user,
        evidence.workdir,
        evidence.state,
        evidence.exit_code,
    )
    if any(
        type(value) is not str
        or not value
        or len(value) > 4096
        or any(character in value for character in "\x00\r\n|")
        for value in strings
    ):
        raise ConsumerVerificationError("scheduler provenance row is malformed")
    try:
        contract.require_safe_token(evidence.cluster, "scheduler evidence cluster")
        contract.require_safe_token(evidence.job_name, "scheduler evidence job name")
        contract.require_safe_token(evidence.user, "scheduler evidence user")
    except contract.ContractError as error:
        raise ConsumerVerificationError(str(error)) from error
    if (
        evidence.job_id != job_id
        or evidence.cluster != cluster
        or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}", evidence.submit_time)
        or not os.path.isabs(evidence.workdir)
    ):
        raise ConsumerVerificationError("scheduler provenance binding drift")
    return evidence


def query_successful_job(job_id: int, cluster: str) -> SchedulerEvidence:
    if type(job_id) is not int or job_id < 1:
        raise ConsumerVerificationError("scheduler job id must be positive")
    try:
        contract.require_safe_token(cluster, "scheduler cluster")
    except contract.ContractError as error:
        raise ConsumerVerificationError(str(error)) from error
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
            env=_safe_environment(),
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ConsumerVerificationError(f"cannot obtain scheduler status: {error}") from error
    rows = []
    for line in completed.stdout.splitlines():
        fields = line.strip().split("|")
        if len(fields) == 10 and fields[-1] == "":
            fields.pop()
        if len(fields) == 9 and fields[0] == str(job_id):
            rows.append(fields[1:])
    if len(rows) != 1:
        raise ConsumerVerificationError("scheduler returned no unique root-allocation row")
    evidence = _require_scheduler_evidence(
        SchedulerEvidence(job_id, *rows[0]), job_id=job_id, cluster=cluster
    )
    if evidence.state != "COMPLETED" or evidence.exit_code != "0:0":
        raise ConsumerVerificationError(
            f"job did not complete successfully: {evidence.state} {evidence.exit_code}"
        )
    return evidence


def _strict_canonical_object(payload: bytes, context: str) -> dict[str, object]:
    value = independent.strict_json(payload, context)
    if type(value) is not dict:
        raise ConsumerVerificationError(f"{context} is not an object")
    if contract.canonical_json_bytes(value) != payload:
        raise ConsumerVerificationError(f"{context} is not canonical JSON")
    return value


def _read_path_no_follow(path: Path, context: str, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ConsumerVerificationError(f"cannot open {context}: {error}") from error
    try:
        descriptor_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(descriptor_stat.st_mode)
            or descriptor_stat.st_nlink != 1
            or stat.S_IMODE(descriptor_stat.st_mode) != 0o444
        ):
            raise ConsumerVerificationError(
                f"{context} is not one immutable mode-0444 regular inode"
            )
        payload = publication.read_fd(descriptor, maximum_bytes=maximum)
        if os.fstat(descriptor).st_size != len(payload):
            raise ConsumerVerificationError(f"{context} changed while read")
        return payload
    finally:
        os.close(descriptor)


def _require_self_digest(value: Mapping[str, object], context: str) -> None:
    stored = value.get("receipt_sha256")
    unhashed = dict(value)
    unhashed.pop("receipt_sha256", None)
    expected = hashlib.sha256(contract.canonical_json_bytes(unhashed)).hexdigest()
    if stored != expected:
        raise ConsumerVerificationError(f"{context} self-digest mismatch")


def read_pending_submission(path: Path) -> dict[str, object]:
    receipt = _strict_canonical_object(
        _read_path_no_follow(path, "pending submission receipt", 128 * 1024),
        "pending submission receipt",
    )
    _require_self_digest(receipt, "pending submission receipt")
    required = {
        "schema",
        "status",
        "decisive",
        "authoritative",
        "revision",
        "published_ref",
        "remote_host",
        "remote_namespace",
        "attempt_id",
        "submission_nonce",
        "dependency",
        "job_id",
        "scheduler_submission",
        "expected_marker_name",
        "contract",
        "python",
        "receipt_sha256",
    }
    if set(receipt) != required:
        raise ConsumerVerificationError("pending submission receipt field set drift")
    if (
        receipt["schema"] != contract.SUBMISSION_SCHEMA
        or receipt["status"] != "submitted_pending_nondecisive"
        or receipt["decisive"] is not False
        or receipt["authoritative"] is not False
    ):
        raise ConsumerVerificationError("submission receipt is not explicitly pending")
    revision = receipt["revision"]
    if type(revision) is not str or len(revision) != 40 or any(
        character not in "0123456789abcdef" for character in revision
    ):
        raise ConsumerVerificationError("submission revision is malformed")
    attempt_id = receipt["attempt_id"]
    nonce = receipt["submission_nonce"]
    if type(attempt_id) is not str or type(nonce) is not str:
        raise ConsumerVerificationError("submission attempt or nonce type is malformed")
    contract.require_safe_token(attempt_id, "submission attempt id", minimum=6)
    contract.require_lower_sha256(nonce, "submission nonce")
    job_id = receipt["job_id"]
    if type(job_id) is not int or job_id < 1:
        raise ConsumerVerificationError("submission job id is malformed")
    if receipt["expected_marker_name"] != f"component-quotient-census-{job_id}.current":
        raise ConsumerVerificationError("submission marker name drift")
    fixed = receipt["contract"]
    if type(fixed) is not dict or set(fixed) != {
        "expected_sources",
        "manifest_relative_path",
        "lock_sha256",
        "manifest_sha256",
        "portable_source_set_sha256",
    }:
        raise ConsumerVerificationError("submission fixed contract binding drift")
    manifest_digest = fixed["manifest_sha256"]
    if type(manifest_digest) is not str:
        raise ConsumerVerificationError("submission manifest digest type drift")
    contract.require_lower_sha256(manifest_digest, "manifest digest")
    if fixed != {
        "expected_sources": contract.EXPECTED_SOURCES,
        "manifest_relative_path": contract.MANIFEST_RELATIVE_PATH,
        "lock_sha256": contract.LOCK_SHA256,
        "manifest_sha256": contract.MANIFEST_SHA256,
        "portable_source_set_sha256": contract.PORTABLE_SOURCE_SET_SHA256,
    }:
        raise ConsumerVerificationError("submission manifest is not the fixed external campaign")
    namespace_binding = receipt["remote_namespace"]
    if type(namespace_binding) is not dict:
        raise ConsumerVerificationError("submission namespace binding is malformed")
    scheduler_submission = receipt["scheduler_submission"]
    if type(scheduler_submission) is not dict or set(scheduler_submission) != {
        "sbatch_parsable",
        "job_id",
        "cluster",
        "job_name",
        "user",
        "workdir",
    }:
        raise ConsumerVerificationError("submission scheduler identity field set drift")
    for field in ("sbatch_parsable", "cluster", "job_name", "user", "workdir"):
        if type(scheduler_submission[field]) is not str:
            raise ConsumerVerificationError("submission scheduler identity type drift")
    cluster = scheduler_submission["cluster"]
    job_name = scheduler_submission["job_name"]
    user = scheduler_submission["user"]
    assert type(cluster) is str and type(job_name) is str and type(user) is str
    contract.require_safe_token(cluster, "submission Slurm cluster")
    contract.require_safe_token(job_name, "submission Slurm job name")
    contract.require_safe_token(user, "submission Slurm user")
    if (
        scheduler_submission["job_id"] != job_id
        or scheduler_submission["sbatch_parsable"] != f"{job_id};{cluster}"
        or scheduler_submission["workdir"] != namespace_binding.get("path")
    ):
        raise ConsumerVerificationError("submission scheduler identity binding drift")
    dependency = receipt["dependency"]
    if dependency is not None and (type(dependency) is not int or dependency < 1):
        raise ConsumerVerificationError("submission dependency is malformed")
    if type(receipt["published_ref"]) is not str or type(receipt["remote_host"]) is not str:
        raise ConsumerVerificationError("submission Git ref or remote host is malformed")
    python_identity = receipt["python"]
    if type(python_identity) is not dict or set(python_identity) != {
        "realpath",
        "version",
        "sha256",
    }:
        raise ConsumerVerificationError("submission Python identity is malformed")
    if (
        type(python_identity["realpath"]) is not str
        or not python_identity["realpath"].startswith("/")
        or type(python_identity["version"]) is not str
        or not python_identity["version"]
        or type(python_identity["sha256"]) is not str
    ):
        raise ConsumerVerificationError("submission Python identity field type drift")
    contract.require_lower_sha256(python_identity["sha256"], "submission Python digest")
    return receipt


def _identity_tuple(value: object, context: str) -> tuple[int, int]:
    if type(value) is not dict:
        raise ConsumerVerificationError(f"{context} is malformed")
    device = value.get("device")
    inode = value.get("inode")
    if type(device) is not int or device < 1 or type(inode) is not int or inode < 1:
        raise ConsumerVerificationError(f"{context} inode identity is malformed")
    return device, inode


def _open_bound_file(
    directory_descriptor: int, name: str, context: str
) -> tuple[int, os.stat_result]:
    descriptor: int | None = None
    try:
        descriptor = publication.open_regular_no_follow(
            directory_descriptor, name, context
        )
        descriptor_stat = os.fstat(descriptor)
        named_stat = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except (OSError, publication.PublicationError) as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ConsumerVerificationError(str(error)) from error
    if (
        descriptor_stat.st_dev != named_stat.st_dev
        or descriptor_stat.st_ino != named_stat.st_ino
        or descriptor_stat.st_nlink != 1
        or stat.S_IMODE(descriptor_stat.st_mode) != 0o444
    ):
        os.close(descriptor)
        raise ConsumerVerificationError(
            f"{context} is replaced, multiply linked, or not mode 0444"
        )
    return descriptor, descriptor_stat


def _archive_members(descriptor: int) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    total_bytes = 0
    try:
        with os.fdopen(os.dup(descriptor), "rb") as handle:
            handle.seek(0)
            with tarfile.open(fileobj=handle, mode="r:") as archive:
                for info in archive:
                    if len(members) >= MAX_ARCHIVE_MEMBERS:
                        raise ConsumerVerificationError(
                            "archive contains too many members"
                        )
                    pure = PurePosixPath(info.name)
                    if (
                        pure.is_absolute()
                        or not pure.parts
                        or str(pure) != info.name
                        or any(part in {"", ".", ".."} for part in pure.parts)
                        or info.name in members
                        or not info.isreg()
                        or info.mode != 0o444
                        or info.mtime != 0
                        or info.uid != 0
                        or info.gid != 0
                    ):
                        raise ConsumerVerificationError(
                            f"unsafe or duplicate archive member {info.name!r}"
                        )
                    member_limit = (
                        independent.CAPS["max_source_bytes"]
                        if info.name.startswith("sources/")
                        else MAX_ARCHIVE_MEMBER_BYTES
                    )
                    total_bytes += info.size
                    if (
                        info.size < 0
                        or info.size > member_limit
                        or total_bytes > MAX_ARCHIVE_TOTAL_BYTES
                    ):
                        raise ConsumerVerificationError(
                            f"archive member size is outside its bound: {info.name}"
                        )
                    extracted = archive.extractfile(info)
                    if extracted is None:
                        raise ConsumerVerificationError(
                            f"archive member cannot be read: {info.name}"
                        )
                    payload = extracted.read(info.size + 1)
                    if len(payload) != info.size:
                        raise ConsumerVerificationError(
                            f"archive member size changed: {info.name}"
                        )
                    members[info.name] = payload
    except (OSError, tarfile.TarError) as error:
        raise ConsumerVerificationError(f"cannot parse immutable archive: {error}") from error
    return members


def _require_exact_keys(value: Mapping[str, object], expected: set[str], context: str) -> None:
    if set(value) != expected:
        raise ConsumerVerificationError(f"{context} field set drift")


def _verify_archive_semantics(
    *,
    members: dict[str, bytes],
    repository_root: Path,
    revision: str,
    expected_manifest_sha256: str,
    expected_namespace: dict[str, object],
    expected_job_id: int,
    expected_attempt_id: str,
    expected_nonce: str,
    expected_runtime_sha256: str,
    expected_environment_sha256: str,
    expected_metadata_sha256: str,
    expected_python: dict[str, object],
    expected_slurm: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    required = {
        "inputs/campaign-lock.json",
        "inputs/manifest.jsonl",
        "outputs/records.jsonl",
        "outputs/aggregate.json",
        "outputs/targets.jsonl",
        "provenance/portable-source-set.jsonl",
        "provenance/runtime-revision-blobs.json",
        "verification/independent-decision.json",
        "logs/analyzer.txt",
        "logs/independent-verifier.txt",
        "metadata.json",
    }
    if not required.issubset(members):
        raise ConsumerVerificationError("archive lacks a required T5 member")
    metadata_bytes = members["metadata.json"]
    if hashlib.sha256(metadata_bytes).hexdigest() != expected_metadata_sha256:
        raise ConsumerVerificationError("bundle metadata digest differs from marker")
    metadata = independent.strict_json(metadata_bytes, "bundle metadata")
    if type(metadata) is not dict:
        raise ConsumerVerificationError("bundle metadata is not an object")
    _require_exact_keys(
        metadata,
        {
            "schema",
            "status",
            "authoritative_without_scheduler_status",
            "revision",
            "job_id",
            "slurm",
            "attempt_id",
            "submission_nonce",
            "remote_namespace",
            "python",
            "runtime_environment",
            "contract",
            "independent_verification",
            "members",
        },
        "bundle metadata",
    )
    if (
        metadata["schema"] != contract.BUNDLE_METADATA_SCHEMA
        or metadata["status"]
        != "verified_publication_nondecisive_without_scheduler_status"
        or metadata["authoritative_without_scheduler_status"] is not False
        or metadata["revision"] != revision
        or metadata["job_id"] != expected_job_id
        or metadata["slurm"] != expected_slurm
        or metadata["attempt_id"] != expected_attempt_id
        or metadata["submission_nonce"] != expected_nonce
        or metadata["remote_namespace"] != expected_namespace
        or metadata["python"] != expected_python
        or metadata["contract"]
        != {
            "lock_sha256": contract.LOCK_SHA256,
            "manifest_sha256": expected_manifest_sha256,
            "portable_source_set_sha256": contract.PORTABLE_SOURCE_SET_SHA256,
            "runtime_revision_blobs_sha256": expected_runtime_sha256,
            "runtime_environment_sha256": expected_environment_sha256,
        }
    ):
        raise ConsumerVerificationError("bundle metadata binding drift")
    environment = metadata["runtime_environment"]
    try:
        runtime_environment.validate_runtime_environment(environment)
    except runtime_environment.RuntimeEnvironmentError as error:
        raise ConsumerVerificationError(str(error)) from error
    metadata_contract = metadata["contract"]
    assert type(metadata_contract) is dict
    environment_digest = hashlib.sha256(
        contract.canonical_json_bytes(environment)
    ).hexdigest()
    if metadata_contract.get("runtime_environment_sha256") != environment_digest:
        raise ConsumerVerificationError("runtime environment digest differs from metadata")
    if environment_digest != expected_environment_sha256:
        raise ConsumerVerificationError("runtime environment digest differs from marker")
    stored_hashes = metadata["members"]
    if type(stored_hashes) is not dict or set(stored_hashes) != set(members) - {"metadata.json"}:
        raise ConsumerVerificationError("bundle member inventory drift")
    for name, payload in members.items():
        if (
            name != "metadata.json"
            and stored_hashes.get(name) != hashlib.sha256(payload).hexdigest()
        ):
            raise ConsumerVerificationError(f"bundle member digest drift: {name}")

    runtime_bytes = members["provenance/runtime-revision-blobs.json"]
    runtime_stored = _strict_canonical_object(runtime_bytes, "runtime blob inventory")
    runtime_fresh = contract.verify_runtime_revision_blobs(repository_root, revision)
    if runtime_stored != runtime_fresh:
        raise ConsumerVerificationError("archived runtime inventory differs from exact revision")
    runtime_digest = hashlib.sha256(contract.canonical_json_bytes(runtime_fresh)).hexdigest()
    if runtime_digest != expected_runtime_sha256:
        raise ConsumerVerificationError("runtime inventory digest differs from marker")
    for relative_path, binding in runtime_fresh.items():
        if not relative_path.startswith("scripts/"):
            continue
        member_name = f"code/{relative_path.removeprefix('scripts/')}"
        payload = members.get(member_name)
        if payload is None or type(binding) is not dict or (
            hashlib.sha256(payload).hexdigest() != binding.get("sha256")
            or len(payload) != binding.get("bytes")
        ):
            raise ConsumerVerificationError(f"archived runtime blob drift: {relative_path}")

    source_prefix = "sources/"
    sources = {
        name.removeprefix(source_prefix): payload
        for name, payload in members.items()
        if name.startswith(source_prefix)
    }
    snapshot = independent.snapshot_from_bytes(
        repository_root=repository_root,
        lock_bytes=members["inputs/campaign-lock.json"],
        manifest_bytes=members["inputs/manifest.jsonl"],
        records_bytes=members["outputs/records.jsonl"],
        aggregate_bytes=members["outputs/aggregate.json"],
        targets_bytes=members["outputs/targets.jsonl"],
        source_bytes=sources,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    expected_names = required | {
        f"sources/{relative_path}" for relative_path in sources
    } | {
        f"code/{relative_path.removeprefix('scripts/')}"
        for relative_path in contract.RUNTIME_PROJECT_FILES
        if relative_path.startswith("scripts/")
    }
    if set(members) != expected_names:
        raise ConsumerVerificationError("archive contains an unexpected or missing member")
    if snapshot.portable_source_bytes != members["provenance/portable-source-set.jsonl"]:
        raise ConsumerVerificationError("portable source inventory differs from captured sources")
    fresh_independent = independent.verify_snapshot(snapshot)
    archived_independent = _strict_canonical_object(
        members["verification/independent-decision.json"],
        "archived independent decision",
    )
    if (
        fresh_independent != archived_independent
        or metadata["independent_verification"] != fresh_independent
    ):
        raise ConsumerVerificationError("fresh and archived independent decisions differ")
    if (
        fresh_independent.get("decisive") is not True
        or fresh_independent.get("validity_pass") is not True
    ):
        raise ConsumerVerificationError("independent decision is not decisive and valid")
    return metadata, fresh_independent


def verify_publication(
    *,
    submission_receipt: Path,
    repository_root: Path,
    final_receipt_name: str | None = None,
    consumer_attempt_id: str | None = None,
    scheduler_query: Callable[[int, str], SchedulerEvidence] = query_successful_job,
    boundary_hook: Callable[[str], None] | None = None,
) -> publication.PublishedFile:
    if not sys.platform.startswith("linux"):
        raise ConsumerVerificationError("T5 consumption requires real Linux O_TMPFILE")
    hostile = contract.hostile_environment_names(dict(os.environ))
    if hostile:
        raise ConsumerVerificationError(
            "hostile ambient environment is forbidden: " + ", ".join(hostile)
        )
    repository_root = Path(os.path.abspath(repository_root))
    if repository_root != ROOT.resolve(strict=True):
        raise ConsumerVerificationError(
            "executing consumer and verified repository root must be identical"
        )
    try:
        receipt = read_pending_submission(submission_receipt)
    except contract.ContractError as error:
        raise ConsumerVerificationError(str(error)) from error
    if consumer_attempt_id is None:
        consumer_attempt_id = secrets.token_hex(16)
    try:
        contract.require_safe_token(
            consumer_attempt_id, "consumer attempt id", minimum=16
        )
    except contract.ContractError as error:
        raise ConsumerVerificationError(str(error)) from error
    job_id = receipt["job_id"]
    assert type(job_id) is int
    scheduler_submission = receipt["scheduler_submission"]
    assert type(scheduler_submission) is dict
    cluster = scheduler_submission["cluster"]
    assert type(cluster) is str
    evidence = _require_scheduler_evidence(
        scheduler_query(job_id, cluster), job_id=job_id, cluster=cluster
    )
    if (
        evidence.job_id != job_id
        or evidence.cluster != cluster
        or evidence.job_name != scheduler_submission["job_name"]
        or evidence.user != scheduler_submission["user"]
        or evidence.workdir != scheduler_submission["workdir"]
        or evidence.state != "COMPLETED"
        or evidence.exit_code != "0:0"
        or not evidence.sluid
        or not evidence.submit_time
    ):
        raise ConsumerVerificationError("scheduler callback did not prove successful root job")
    namespace = receipt["remote_namespace"]
    if type(namespace) is not dict:
        raise ConsumerVerificationError("submission namespace binding is malformed")
    _require_exact_keys(
        namespace,
        {"id", "path", "device", "inode", "results_path", "results_device", "results_inode"},
        "submission namespace",
    )
    if (
        type(namespace["id"]) is not str
        or type(namespace["path"]) is not str
        or type(namespace["results_path"]) is not str
    ):
        raise ConsumerVerificationError("submission namespace string field type drift")
    namespace_id = contract.require_lower_sha256(namespace["id"], "namespace id")
    namespace_path = Path(namespace["path"])
    expected_namespace = _identity_tuple(namespace, "submission namespace")
    results_identity = {
        "device": namespace["results_device"],
        "inode": namespace["results_inode"],
    }
    expected_results = _identity_tuple(results_identity, "submission results directory")
    if namespace["results_path"] != str(namespace_path / "results"):
        raise ConsumerVerificationError("submission result path is not under its namespace")
    submission_nonce = receipt["submission_nonce"]
    assert type(submission_nonce) is str
    try:
        recomputed_namespace_id = contract.namespace_identity_sha256(
            namespace_path=str(namespace_path),
            namespace_device=expected_namespace[0],
            namespace_inode=expected_namespace[1],
            results_device=expected_results[0],
            results_inode=expected_results[1],
            submission_nonce=submission_nonce,
        )
    except contract.ContractError as error:
        raise ConsumerVerificationError(str(error)) from error
    if recomputed_namespace_id != namespace_id:
        raise ConsumerVerificationError("submission namespace identity digest drift")
    pinned: publication.PinnedResultRoot | None = None
    marker_descriptor: int | None = None
    archive_descriptor: int | None = None
    try:
        pinned = publication.PinnedResultRoot.open(
            namespace_path,
            expected_namespace=expected_namespace,
            expected_results=expected_results,
        )
        if pinned.identity_json(namespace_id) != namespace:
            raise ConsumerVerificationError("fresh namespace identity differs from submission")
        if boundary_hook is not None:
            boundary_hook("directories_opened")
        pinned.verify_paths()
        marker_name = receipt["expected_marker_name"]
        assert type(marker_name) is str
        marker_descriptor, marker_stat = _open_bound_file(
            pinned.results_descriptor, marker_name, "canonical marker"
        )
        if boundary_hook is not None:
            boundary_hook("marker_opened")
        marker_bytes = publication.read_fd(marker_descriptor, maximum_bytes=256 * 1024)
        marker_sha256 = hashlib.sha256(marker_bytes).hexdigest()
        marker = _strict_canonical_object(marker_bytes, "canonical marker")
        if boundary_hook is not None:
            boundary_hook("marker_hashed")
        _require_exact_keys(
            marker,
            {
                "schema",
                "status",
                "authoritative_without_successful_job_status",
                "final_archive",
                "revision",
                "job_id",
                "slurm",
                "attempt_id",
                "submission_nonce",
                "remote_namespace",
                "contract",
                "independent_receipt_sha256",
                "bundle_metadata_sha256",
            },
            "canonical marker",
        )
        fixed = receipt["contract"]
        assert type(fixed) is dict
        if (
            marker["schema"] != contract.MARKER_SCHEMA
            or marker["status"] != "verified_publication_nondecisive_without_scheduler_status"
            or marker["authoritative_without_successful_job_status"] is not False
            or marker["revision"] != receipt["revision"]
            or marker["job_id"] != job_id
            or marker["slurm"] != scheduler_submission
            or marker["attempt_id"] != receipt["attempt_id"]
            or marker["submission_nonce"] != receipt["submission_nonce"]
            or marker["remote_namespace"] != namespace
            or marker["contract"]
            != {
                "lock_sha256": contract.LOCK_SHA256,
                "manifest_sha256": fixed["manifest_sha256"],
                "portable_source_set_sha256": contract.PORTABLE_SOURCE_SET_SHA256,
                "runtime_revision_blobs_sha256": marker["contract"].get(
                    "runtime_revision_blobs_sha256"
                )
                if type(marker["contract"]) is dict
                else None,
                "runtime_environment_sha256": marker["contract"].get(
                    "runtime_environment_sha256"
                )
                if type(marker["contract"]) is dict
                else None,
            }
        ):
            raise ConsumerVerificationError("canonical marker binding drift")
        marker_contract = marker["contract"]
        assert type(marker_contract) is dict
        if type(marker_contract["runtime_revision_blobs_sha256"]) is not str:
            raise ConsumerVerificationError("runtime inventory digest type drift")
        runtime_sha256 = contract.require_lower_sha256(
            marker_contract["runtime_revision_blobs_sha256"],
            "runtime inventory digest",
        )
        if type(marker_contract["runtime_environment_sha256"]) is not str:
            raise ConsumerVerificationError("runtime environment digest type drift")
        environment_sha256 = contract.require_lower_sha256(
            marker_contract["runtime_environment_sha256"],
            "runtime environment digest",
        )
        if type(marker["bundle_metadata_sha256"]) is not str:
            raise ConsumerVerificationError("bundle metadata digest type drift")
        metadata_sha256 = contract.require_lower_sha256(
            marker["bundle_metadata_sha256"], "bundle metadata digest"
        )
        final_archive = marker["final_archive"]
        if type(final_archive) is not dict:
            raise ConsumerVerificationError("marker final archive binding is malformed")
        _require_exact_keys(
            final_archive,
            {"name", "sha256", "bytes", "device", "inode", "mode", "link_count"},
            "marker final archive",
        )
        for field in ("bytes", "device", "inode", "link_count"):
            if type(final_archive[field]) is not int or final_archive[field] < 1:
                raise ConsumerVerificationError(
                    f"marker final archive {field} is malformed"
                )
        if (
            type(final_archive["name"]) is not str
            or type(final_archive["sha256"]) is not str
            or type(final_archive["mode"]) is not str
        ):
            raise ConsumerVerificationError("marker final archive string field type drift")
        archive_name = contract.require_safe_token(
            final_archive["name"], "final archive name", minimum=8
        )
        expected_archive_name = (
            f"component-quotient-census-{job_id}-attempt-{marker['attempt_id']}.tar"
        )
        if archive_name != expected_archive_name:
            raise ConsumerVerificationError("marker archive name drift")
        archive_sha256 = contract.require_lower_sha256(
            final_archive["sha256"], "archive digest"
        )
        archive_descriptor, archive_stat = _open_bound_file(
            pinned.results_descriptor, archive_name, "final archive"
        )
        if boundary_hook is not None:
            boundary_hook("archive_opened")
        if (
            final_archive["bytes"] != archive_stat.st_size
            or final_archive["device"] != archive_stat.st_dev
            or final_archive["inode"] != archive_stat.st_ino
            or final_archive["mode"] != "0444"
            or final_archive["link_count"] != 1
        ):
            raise ConsumerVerificationError("fresh archive inode differs from marker")
        fresh_archive_sha256 = publication.sha256_fd(archive_descriptor)
        if fresh_archive_sha256 != archive_sha256:
            raise ConsumerVerificationError("fresh archive digest differs from marker")
        if boundary_hook is not None:
            boundary_hook("archive_hashed")
        members = _archive_members(archive_descriptor)
        if boundary_hook is not None:
            boundary_hook("archive_parsed")
        metadata, decision = _verify_archive_semantics(
            members=members,
            repository_root=repository_root,
            revision=str(receipt["revision"]),
            expected_manifest_sha256=str(fixed["manifest_sha256"]),
            expected_namespace=namespace,
            expected_job_id=job_id,
            expected_attempt_id=str(marker["attempt_id"]),
            expected_nonce=str(receipt["submission_nonce"]),
            expected_runtime_sha256=runtime_sha256,
            expected_environment_sha256=environment_sha256,
            expected_metadata_sha256=metadata_sha256,
            expected_python=receipt["python"],  # type: ignore[arg-type]
            expected_slurm=scheduler_submission,
        )
        if marker["independent_receipt_sha256"] != decision["receipt_sha256"]:
            raise ConsumerVerificationError("marker independent receipt binding drift")
        if boundary_hook is not None:
            boundary_hook("semantic_verified")
        pinned.verify_paths()
        publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=marker_name,
            expected_descriptor=marker_descriptor,
            expected_sha256=marker_sha256,
            expected_payload=marker_bytes,
        )
        publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=archive_name,
            expected_descriptor=archive_descriptor,
            expected_sha256=archive_sha256,
        )
        final_receipt: dict[str, object] = {
            "schema": contract.FINAL_RECEIPT_SCHEMA,
            "status": "verified_complete_requires_successful_consumer_exit",
            "decisive": True,
            "authoritative_without_successful_consumer_exit": False,
            "scheduler": evidence.to_json(),
            "scheduler_submission": scheduler_submission,
            "revision": receipt["revision"],
            "job_id": job_id,
            "attempt_id": marker["attempt_id"],
            "consumer_attempt_id": consumer_attempt_id,
            "submission_nonce": receipt["submission_nonce"],
            "remote_namespace": namespace,
            "contract": marker_contract,
            "publication": {
                "archive": {
                    "name": archive_name,
                    "sha256": archive_sha256,
                    "bytes": archive_stat.st_size,
                    "device": archive_stat.st_dev,
                    "inode": archive_stat.st_ino,
                    "mode": "0444",
                    "link_count": 1,
                },
                "marker": {
                    "name": marker_name,
                    "sha256": marker_sha256,
                    "bytes": marker_stat.st_size,
                    "device": marker_stat.st_dev,
                    "inode": marker_stat.st_ino,
                    "mode": "0444",
                    "link_count": 1,
                },
                "bundle_metadata_sha256": metadata_sha256,
            },
            "independent_decision": decision,
            "submission_receipt_sha256": receipt["receipt_sha256"],
            "bundle_metadata": metadata,
        }
        final_receipt["receipt_sha256"] = hashlib.sha256(
            contract.canonical_json_bytes(final_receipt)
        ).hexdigest()
        final_receipt_bytes = contract.canonical_json_bytes(final_receipt)
        expected_receipt_name = (
            f"component-quotient-census-{job_id}-consumer-"
            f"{consumer_attempt_id}.receipt.json"
        )
        if final_receipt_name is not None and final_receipt_name != expected_receipt_name:
            raise ConsumerVerificationError("final receipt name violates the fixed contract")
        if boundary_hook is not None:
            boundary_hook("receipt_ready")
        pinned.verify_paths()
        publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=marker_name,
            expected_descriptor=marker_descriptor,
            expected_sha256=marker_sha256,
            expected_payload=marker_bytes,
        )
        publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=archive_name,
            expected_descriptor=archive_descriptor,
            expected_sha256=archive_sha256,
        )
        published = publication.publish_bytes_no_replace(
            directory_descriptor=pinned.results_descriptor,
            name=expected_receipt_name,
            payload=final_receipt_bytes,
            boundary_hook=boundary_hook,
            hook_prefix="receipt",
        )
        if boundary_hook is not None:
            boundary_hook("before_return")
        pinned.verify_paths()
        publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=marker_name,
            expected_descriptor=marker_descriptor,
            expected_sha256=marker_sha256,
            expected_payload=marker_bytes,
        )
        publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=archive_name,
            expected_descriptor=archive_descriptor,
            expected_sha256=archive_sha256,
        )
        receipt_stat = publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=expected_receipt_name,
            expected_descriptor=None,
            expected_sha256=published.sha256,
            expected_payload=final_receipt_bytes,
        )
        if (
            receipt_stat.st_dev != published.stat.st_dev
            or receipt_stat.st_ino != published.stat.st_ino
        ):
            raise ConsumerVerificationError(
                "final consumer receipt changed after descriptor publication"
            )
        return published
    except (
        contract.ContractError,
        independent.IndependentVerificationError,
        publication.PublicationError,
        OSError,
    ) as error:
        raise ConsumerVerificationError(str(error)) from error
    finally:
        for descriptor in (archive_descriptor, marker_descriptor):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if pinned is not None:
            pinned.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--submission-receipt", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--final-receipt-name")
    parser.add_argument("--consumer-attempt-id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        published = verify_publication(
            submission_receipt=args.submission_receipt,
            repository_root=args.repository_root,
            final_receipt_name=args.final_receipt_name,
            consumer_attempt_id=args.consumer_attempt_id,
        )
    except ConsumerVerificationError as error:
        raise SystemExit(f"T5 consumer verification failed: {error}")
    print(
        f"t5_authoritative=true receipt={published.name} "
        f"receipt_sha256={published.sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
