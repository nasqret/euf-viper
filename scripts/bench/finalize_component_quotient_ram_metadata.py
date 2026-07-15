#!/usr/bin/env python3
"""Independently verify and descriptor-publish one T5 archive and marker."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import stat
import sys
import tarfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import component_quotient_contract as contract  # noqa: E402
from scripts.bench import independent_component_quotient_verifier as independent  # noqa: E402
from scripts.bench import t5_linux_publication as publication  # noqa: E402
from scripts.bench import t5_runtime_environment as runtime_environment  # noqa: E402


class BundlePublicationError(ValueError):
    """Raised when the T5 artifact cannot be proven and published."""


@dataclass(frozen=True)
class PublishedBundle:
    path: Path
    current_marker: Path
    sha256: str
    marker_sha256: str
    metadata: dict[str, object]
    marker: dict[str, object]


def _read_regular(path: Path, context: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BundlePublicationError(f"cannot open {context} {path}: {error}") from error
    try:
        descriptor_stat = os.fstat(descriptor)
        if not stat.S_ISREG(descriptor_stat.st_mode):
            raise BundlePublicationError(f"{context} is not a regular file")
        payload = publication.read_fd(descriptor)
        if os.fstat(descriptor).st_size != len(payload):
            raise BundlePublicationError(f"{context} changed while captured")
        return payload
    finally:
        os.close(descriptor)


def _capture_python_identity(
    expected_realpath: Path,
    expected_version: str,
    expected_sha256: str,
) -> dict[str, str]:
    try:
        resolved = expected_realpath.resolve(strict=True)
        running = Path(sys.executable).resolve(strict=True)
    except OSError as error:
        raise BundlePublicationError(f"cannot resolve pinned Python: {error}") from error
    if resolved != expected_realpath or running != expected_realpath:
        raise BundlePublicationError("pinned Python realpath drift")
    if platform.python_version() != expected_version:
        raise BundlePublicationError("pinned Python version drift")
    digest = hashlib.sha256(_read_regular(resolved, "Python executable")).hexdigest()
    if digest != expected_sha256:
        raise BundlePublicationError("pinned Python SHA-256 drift")
    return {
        "realpath": str(resolved),
        "version": expected_version,
        "sha256": expected_sha256,
    }


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o444
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def _write_archive(descriptor: int, members: MappingStringBytes) -> None:
    try:
        with os.fdopen(os.dup(descriptor), "w+b") as handle:
            with tarfile.open(
                fileobj=handle, mode="w", format=tarfile.USTAR_FORMAT
            ) as archive:
                for name, payload in sorted(members.items()):
                    archive.addfile(_tar_info(name, len(payload)), io.BytesIO(payload))
            handle.flush()
            os.fsync(handle.fileno())
    except (OSError, ValueError, tarfile.TarError) as error:
        raise BundlePublicationError(f"cannot write unnamed archive: {error}") from error


MappingStringBytes = dict[str, bytes]


def _strict_receipt(payload: bytes) -> dict[str, object]:
    value = independent.strict_json(payload, "standalone independent receipt")
    if type(value) is not dict:
        raise BundlePublicationError("standalone independent receipt is not an object")
    if contract.canonical_json_bytes(value) != payload:
        raise BundlePublicationError("standalone independent receipt is not canonical")
    stored_digest = value.get("receipt_sha256")
    unhashed = dict(value)
    unhashed.pop("receipt_sha256", None)
    if stored_digest != hashlib.sha256(contract.canonical_json_bytes(unhashed)).hexdigest():
        raise BundlePublicationError("standalone independent receipt digest drift")
    return value


def _archive_members(
    snapshot: independent.IndependentSnapshot,
    independent_receipt_bytes: bytes,
    runtime_bindings: dict[str, dict[str, object]],
    run_log_bytes: bytes,
    verification_log_bytes: bytes,
    metadata: dict[str, object],
) -> MappingStringBytes:
    members: MappingStringBytes = {
        "inputs/campaign-lock.json": snapshot.lock_bytes,
        "inputs/manifest.jsonl": snapshot.manifest_bytes,
        "outputs/records.jsonl": snapshot.records_bytes,
        "outputs/aggregate.json": snapshot.aggregate_bytes,
        "outputs/targets.jsonl": snapshot.targets_bytes,
        "provenance/portable-source-set.jsonl": snapshot.portable_source_bytes,
        "provenance/runtime-revision-blobs.json": contract.canonical_json_bytes(
            runtime_bindings
        ),
        "verification/independent-decision.json": independent_receipt_bytes,
        "logs/analyzer.txt": run_log_bytes,
        "logs/independent-verifier.txt": verification_log_bytes,
    }
    for relative_path in contract.RUNTIME_PROJECT_FILES:
        if relative_path.startswith("scripts/"):
            payload = _read_regular(
                snapshot.repository_root / relative_path, f"runtime source {relative_path}"
            )
            binding = runtime_bindings[relative_path]
            if (
                binding.get("sha256") != hashlib.sha256(payload).hexdigest()
                or binding.get("bytes") != len(payload)
            ):
                raise BundlePublicationError(
                    f"runtime source changed after revision verification: {relative_path}"
                )
            members[f"code/{relative_path.removeprefix('scripts/')}"] = payload
    for source in snapshot.sources:
        members[f"sources/{source.relative_path}"] = source.source_bytes
    metadata["members"] = {
        name: hashlib.sha256(payload).hexdigest()
        for name, payload in sorted(members.items())
    }
    members["metadata.json"] = json.dumps(
        metadata, indent=2, sort_keys=True
    ).encode("ascii") + b"\n"
    return members


def _require_identity(value: int, context: str) -> int:
    if type(value) is not int or value < 1:
        raise BundlePublicationError(f"{context} must be a positive integer")
    return value


def publish_verified_bundle(
    *,
    final_bundle: Path,
    current_marker: Path,
    attempt_id: str,
    submission_nonce: str,
    namespace_root: Path,
    namespace_id: str,
    namespace_device: int,
    namespace_inode: int,
    results_device: int,
    results_inode: int,
    repository_root: Path,
    manifest_path: Path,
    expected_manifest_sha256: str,
    lock_path: Path,
    records_path: Path,
    aggregate_path: Path,
    targets_path: Path,
    verification_path: Path,
    run_log_path: Path,
    verification_log_path: Path,
    revision: str,
    job_id: int,
    sbatch_parsable: str,
    slurm_cluster: str,
    job_name: str,
    job_user: str,
    workdir: Path,
    python_realpath: Path,
    python_version: str,
    python_sha256: str,
    boundary_hook: Callable[[str], None] | None = None,
) -> PublishedBundle:
    """Publish immutable archive/marker inodes or fail with only stale orphans."""

    if not sys.platform.startswith("linux"):
        raise BundlePublicationError("T5 publication requires real Linux O_TMPFILE")
    hostile = contract.hostile_environment_names(dict(os.environ))
    if hostile:
        raise BundlePublicationError(
            "hostile ambient environment is forbidden: " + ", ".join(hostile)
        )
    try:
        contract.require_safe_token(attempt_id, "attempt id", minimum=6)
        contract.require_lower_sha256(submission_nonce, "submission nonce")
        contract.require_lower_sha256(namespace_id, "remote namespace id")
        contract.require_lower_sha256(expected_manifest_sha256, "manifest digest")
        contract.require_lower_sha256(python_sha256, "Python digest")
    except contract.ContractError as error:
        raise BundlePublicationError(str(error)) from error
    if expected_manifest_sha256 != contract.MANIFEST_SHA256:
        raise BundlePublicationError("manifest digest differs from the fixed external campaign")
    _require_identity(job_id, "job id")
    try:
        contract.require_safe_token(slurm_cluster, "Slurm cluster")
        contract.require_safe_token(job_name, "Slurm job name")
        contract.require_safe_token(job_user, "Slurm job user")
    except contract.ContractError as error:
        raise BundlePublicationError(str(error)) from error
    if sbatch_parsable != f"{job_id};{slurm_cluster}":
        raise BundlePublicationError("sbatch --parsable job/cluster identity drift")
    expected_namespace = (
        _require_identity(namespace_device, "namespace device"),
        _require_identity(namespace_inode, "namespace inode"),
    )
    expected_results = (
        _require_identity(results_device, "results device"),
        _require_identity(results_inode, "results inode"),
    )
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise BundlePublicationError("revision must be a full lowercase Git SHA-1")
    expected_bundle_name = (
        f"component-quotient-census-{job_id}-attempt-{attempt_id}.tar"
    )
    expected_marker_name = f"component-quotient-census-{job_id}.current"
    final_bundle = Path(os.path.abspath(final_bundle))
    current_marker = Path(os.path.abspath(current_marker))
    namespace_root = Path(os.path.abspath(namespace_root))
    repository_root = Path(os.path.abspath(repository_root))
    if repository_root != ROOT.resolve(strict=True):
        raise BundlePublicationError(
            "executing finalizer and verified repository root must be identical"
        )
    if Path(os.path.abspath(lock_path)) != repository_root / contract.LOCK_RELATIVE_PATH:
        raise BundlePublicationError("campaign lock path is not the fixed revision path")
    try:
        contract.require_campaign_manifest_path(repository_root, manifest_path)
    except contract.ContractError as error:
        raise BundlePublicationError(str(error)) from error
    if final_bundle.name != expected_bundle_name or current_marker.name != expected_marker_name:
        raise BundlePublicationError("archive or marker name violates the fixed contract")
    if (
        final_bundle.parent != namespace_root / "results"
        or current_marker.parent != final_bundle.parent
    ):
        raise BundlePublicationError("publication paths leave the bound result namespace")
    if Path(os.path.abspath(workdir)) != namespace_root:
        raise BundlePublicationError("Slurm workdir differs from the bound result namespace")
    try:
        recomputed_namespace_id = contract.namespace_identity_sha256(
            namespace_path=str(namespace_root),
            namespace_device=expected_namespace[0],
            namespace_inode=expected_namespace[1],
            results_device=expected_results[0],
            results_inode=expected_results[1],
            submission_nonce=submission_nonce,
        )
    except contract.ContractError as error:
        raise BundlePublicationError(str(error)) from error
    if recomputed_namespace_id != namespace_id:
        raise BundlePublicationError("remote namespace identity digest drift")

    pinned: publication.PinnedResultRoot | None = None
    archive_descriptor: int | None = None
    archive_writable_descriptor: int | None = None
    marker_descriptor: int | None = None
    marker_writable_descriptor: int | None = None
    try:
        pinned = publication.PinnedResultRoot.open(
            namespace_root,
            expected_namespace=expected_namespace,
            expected_results=expected_results,
        )
        if boundary_hook is not None:
            boundary_hook("directories_opened")
        pinned.verify_paths()
        runtime_bindings = contract.verify_runtime_revision_blobs(
            repository_root, revision
        )
        runtime_bindings_sha256 = hashlib.sha256(
            contract.canonical_json_bytes(runtime_bindings)
        ).hexdigest()
        python_identity = _capture_python_identity(
            python_realpath, python_version, python_sha256
        )
        manifest_bytes = _read_regular(manifest_path, "external campaign manifest")
        try:
            contract.require_campaign_manifest_bytes(manifest_bytes)
        except contract.ContractError as error:
            raise BundlePublicationError(str(error)) from error
        slurm_identity: dict[str, object] = {
            "sbatch_parsable": sbatch_parsable,
            "job_id": job_id,
            "cluster": slurm_cluster,
            "job_name": job_name,
            "user": job_user,
            "workdir": str(namespace_root),
        }
        try:
            environment = runtime_environment.capture_runtime_environment(
                repository_root=repository_root,
                manifest_path=manifest_path,
                namespace_root=namespace_root,
                results_path=namespace_root / "results",
                python_realpath=python_realpath,
                python_version=python_version,
                python_sha256=python_sha256,
                slurm=slurm_identity,
            )
            runtime_environment.validate_runtime_environment(environment)
        except runtime_environment.RuntimeEnvironmentError as error:
            raise BundlePublicationError(str(error)) from error
        environment_sha256 = hashlib.sha256(
            contract.canonical_json_bytes(environment)
        ).hexdigest()
        snapshot = independent.capture_snapshot(
            repository_root=repository_root,
            lock_path=lock_path,
            manifest_path=manifest_path,
            records_path=records_path,
            aggregate_path=aggregate_path,
            targets_path=targets_path,
            expected_manifest_sha256=expected_manifest_sha256,
        )
        fresh_receipt = independent.verify_snapshot(snapshot)
        if (
            fresh_receipt.get("decisive") is not True
            or fresh_receipt.get("validity_pass") is not True
        ):
            raise BundlePublicationError("independent decision is not decisive and valid")
        fresh_receipt_bytes = contract.canonical_json_bytes(fresh_receipt)
        supplied_receipt_bytes = _read_regular(
            verification_path, "standalone independent receipt"
        )
        supplied_receipt = _strict_receipt(supplied_receipt_bytes)
        if supplied_receipt != fresh_receipt:
            raise BundlePublicationError("standalone and fresh independent receipts differ")
        namespace_json = pinned.identity_json(namespace_id)
        metadata: dict[str, object] = {
            "schema": contract.BUNDLE_METADATA_SCHEMA,
            "status": "verified_publication_nondecisive_without_scheduler_status",
            "authoritative_without_scheduler_status": False,
            "revision": revision,
            "job_id": job_id,
            "slurm": slurm_identity,
            "attempt_id": attempt_id,
            "submission_nonce": submission_nonce,
            "remote_namespace": namespace_json,
            "python": python_identity,
            "runtime_environment": environment,
            "contract": {
                "lock_sha256": contract.LOCK_SHA256,
                "manifest_sha256": expected_manifest_sha256,
                "portable_source_set_sha256": contract.PORTABLE_SOURCE_SET_SHA256,
                "runtime_revision_blobs_sha256": runtime_bindings_sha256,
                "runtime_environment_sha256": environment_sha256,
            },
            "independent_verification": fresh_receipt,
        }
        members = _archive_members(
            snapshot,
            fresh_receipt_bytes,
            runtime_bindings,
            _read_regular(run_log_path, "analyzer log"),
            _read_regular(verification_log_path, "independent verifier log"),
            metadata,
        )
        archive_writable_descriptor = publication.open_unnamed_linkable_file(
            pinned.results_descriptor
        )
        _write_archive(archive_writable_descriptor, members)
        archive_sha256, archive_unlinked_stat = publication.seal_unnamed_file(
            archive_writable_descriptor
        )
        if archive_unlinked_stat.st_nlink != 0:
            raise BundlePublicationError("archive acquired a staging link")
        if boundary_hook is not None:
            boundary_hook("archive_ready")
        pinned.verify_paths()
        publication.link_unnamed_inode_no_replace(
            archive_writable_descriptor,
            pinned.results_descriptor,
            final_bundle.name,
        )
        archive_descriptor = publication.reopen_linked_inode_read_only(
            archive_writable_descriptor,
            pinned.results_descriptor,
            final_bundle.name,
        )
        os.close(archive_writable_descriptor)
        archive_writable_descriptor = None
        if boundary_hook is not None:
            boundary_hook("archive_linked")
        publication.fsync_directory(pinned.results_descriptor)
        archive_stat = publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=final_bundle.name,
            expected_descriptor=archive_descriptor,
            expected_sha256=archive_sha256,
        )
        if boundary_hook is not None:
            boundary_hook("archive_verified")
        pinned.verify_paths()
        publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=final_bundle.name,
            expected_descriptor=archive_descriptor,
            expected_sha256=archive_sha256,
        )
        marker: dict[str, object] = {
            "schema": contract.MARKER_SCHEMA,
            "status": "verified_publication_nondecisive_without_scheduler_status",
            "authoritative_without_successful_job_status": False,
            "final_archive": {
                "name": final_bundle.name,
                "sha256": archive_sha256,
                "bytes": archive_stat.st_size,
                "device": archive_stat.st_dev,
                "inode": archive_stat.st_ino,
                "mode": "0444",
                "link_count": 1,
            },
            "revision": revision,
            "job_id": job_id,
            "slurm": slurm_identity,
            "attempt_id": attempt_id,
            "submission_nonce": submission_nonce,
            "remote_namespace": namespace_json,
            "contract": metadata["contract"],
            "independent_receipt_sha256": fresh_receipt["receipt_sha256"],
            "bundle_metadata_sha256": hashlib.sha256(
                members["metadata.json"]
            ).hexdigest(),
        }
        marker_bytes = contract.canonical_json_bytes(marker)
        (
            marker_writable_descriptor,
            marker_sha256,
            _,
        ) = publication.prepare_unnamed_bytes(pinned.results_descriptor, marker_bytes)
        if boundary_hook is not None:
            boundary_hook("marker_ready")
        pinned.verify_paths()
        publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=final_bundle.name,
            expected_descriptor=archive_descriptor,
            expected_sha256=archive_sha256,
        )
        publication.link_unnamed_inode_no_replace(
            marker_writable_descriptor,
            pinned.results_descriptor,
            current_marker.name,
        )
        marker_descriptor = publication.reopen_linked_inode_read_only(
            marker_writable_descriptor,
            pinned.results_descriptor,
            current_marker.name,
        )
        os.close(marker_writable_descriptor)
        marker_writable_descriptor = None
        if boundary_hook is not None:
            boundary_hook("marker_linked")
        publication.fsync_directory(pinned.results_descriptor)
        publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=current_marker.name,
            expected_descriptor=marker_descriptor,
            expected_sha256=marker_sha256,
            expected_payload=marker_bytes,
        )
        if boundary_hook is not None:
            boundary_hook("marker_verified")
        pinned.verify_paths()
        publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=final_bundle.name,
            expected_descriptor=archive_descriptor,
            expected_sha256=archive_sha256,
        )
        publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=current_marker.name,
            expected_descriptor=marker_descriptor,
            expected_sha256=marker_sha256,
            expected_payload=marker_bytes,
        )
        if boundary_hook is not None:
            boundary_hook("before_return")
        pinned.verify_paths()
        publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=final_bundle.name,
            expected_descriptor=archive_descriptor,
            expected_sha256=archive_sha256,
        )
        publication.verify_named_file(
            directory_descriptor=pinned.results_descriptor,
            name=current_marker.name,
            expected_descriptor=marker_descriptor,
            expected_sha256=marker_sha256,
            expected_payload=marker_bytes,
        )
        return PublishedBundle(
            final_bundle,
            current_marker,
            archive_sha256,
            marker_sha256,
            metadata,
            marker,
        )
    except (
        independent.IndependentVerificationError,
        contract.ContractError,
        publication.PublicationError,
        OSError,
    ) as error:
        raise BundlePublicationError(str(error)) from error
    finally:
        for descriptor in (
            marker_descriptor,
            marker_writable_descriptor,
            archive_descriptor,
            archive_writable_descriptor,
        ):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if pinned is not None:
            pinned.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--final-bundle", type=Path, required=True)
    parser.add_argument("--current-marker", type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--submission-nonce", required=True)
    parser.add_argument("--namespace-root", type=Path, required=True)
    parser.add_argument("--namespace-id", required=True)
    parser.add_argument("--namespace-device", type=int, required=True)
    parser.add_argument("--namespace-inode", type=int, required=True)
    parser.add_argument("--results-device", type=int, required=True)
    parser.add_argument("--results-inode", type=int, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--aggregate", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--verification", type=Path, required=True)
    parser.add_argument("--run-log", type=Path, required=True)
    parser.add_argument("--verification-log", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--job-id", type=int, required=True)
    parser.add_argument("--sbatch-parsable", required=True)
    parser.add_argument("--slurm-cluster", required=True)
    parser.add_argument("--job-name", required=True)
    parser.add_argument("--job-user", required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--python-realpath", type=Path, required=True)
    parser.add_argument("--python-version", required=True)
    parser.add_argument("--python-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        publish_verified_bundle(
            final_bundle=args.final_bundle,
            current_marker=args.current_marker,
            attempt_id=args.attempt_id,
            submission_nonce=args.submission_nonce,
            namespace_root=args.namespace_root,
            namespace_id=args.namespace_id,
            namespace_device=args.namespace_device,
            namespace_inode=args.namespace_inode,
            results_device=args.results_device,
            results_inode=args.results_inode,
            repository_root=args.repository_root,
            manifest_path=args.manifest,
            expected_manifest_sha256=args.expected_manifest_sha256,
            lock_path=args.lock,
            records_path=args.records,
            aggregate_path=args.aggregate,
            targets_path=args.targets,
            verification_path=args.verification,
            run_log_path=args.run_log,
            verification_log_path=args.verification_log,
            revision=args.revision,
            job_id=args.job_id,
            sbatch_parsable=args.sbatch_parsable,
            slurm_cluster=args.slurm_cluster,
            job_name=args.job_name,
            job_user=args.job_user,
            workdir=args.workdir,
            python_realpath=args.python_realpath,
            python_version=args.python_version,
            python_sha256=args.python_sha256,
        )
    except BundlePublicationError as error:
        raise SystemExit(f"component quotient publication failed: {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
