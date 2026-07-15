#!/usr/bin/env python3
"""Run the full T5 prepare/analyze/finalize/consumer path in one Linux clone."""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import stat
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import census_component_quotient_ram as census  # noqa: E402
from scripts.bench import component_quotient_contract as contract  # noqa: E402
from scripts.bench import finalize_component_quotient_ram_metadata as finalizer  # noqa: E402
from scripts.bench import independent_component_quotient_verifier as independent  # noqa: E402
from scripts.bench import t5_linux_publication as publication  # noqa: E402
from scripts.bench import verify_component_quotient_publication as consumer  # noqa: E402


def _write_immutable(path: Path, payload: bytes) -> None:
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
        publication.write_all(descriptor, payload)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
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


def main() -> int:
    if not sys.platform.startswith("linux"):
        raise SystemExit("T5 Linux end-to-end driver requires Linux")
    hostile = contract.hostile_environment_names(dict(os.environ))
    if hostile:
        raise SystemExit("hostile driver environment: " + ", ".join(hostile))
    manifest = ROOT / contract.MANIFEST_RELATIVE_PATH
    contract.require_campaign_manifest_path(ROOT, manifest)
    manifest_bytes = manifest.read_bytes()
    rows = contract.require_campaign_manifest_bytes(manifest_bytes)
    if len(rows) != 7503:
        raise SystemExit("the end-to-end manifest guard did not observe 7,503 rows")
    official = ROOT / contract.OFFICIAL_MANIFEST_RELATIVE_PATH
    if manifest.resolve(strict=True) == official.resolve(strict=True):
        raise SystemExit("external manifest aliases the tracked official manifest")

    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
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
    subprocess.run(
        [str(ROOT / "scripts/wmi/check_component_quotient_checkout.sh"), revision],
        cwd=ROOT,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
        },
        check=True,
    )

    results = ROOT / "results"
    results.mkdir(mode=0o700)
    work = ROOT / "t5-e2e-work"
    work.mkdir(mode=0o700)
    records = work / "records.jsonl"
    aggregate = work / "aggregate.json"
    targets = work / "targets.jsonl"
    verification = work / "independent-decision.json"
    analyzer_log = work / "analyzer.txt"
    verifier_log = work / "independent-verifier.txt"

    job_id = int(os.environ.get("EUF_VIPER_T5_E2E_JOB_ID", "987654321"))
    cluster = os.environ.get("EUF_VIPER_T5_E2E_CLUSTER", "t5-e2e-linux")
    job_name = "euf-cqram-census"
    job_user = getpass.getuser()
    attempt_id = f"component-quotient-{revision[:12]}-attempt.E2E7503A"
    nonce = hashlib.sha256(f"{revision}:{job_id}:t5-e2e".encode("ascii")).hexdigest()
    namespace_stat = ROOT.stat()
    results_stat = results.stat()
    namespace_id = contract.namespace_identity_sha256(
        namespace_path=str(ROOT),
        namespace_device=namespace_stat.st_dev,
        namespace_inode=namespace_stat.st_ino,
        results_device=results_stat.st_dev,
        results_inode=results_stat.st_ino,
        submission_nonce=nonce,
    )
    python_realpath = Path(sys.executable).resolve(strict=True)
    python_sha256 = hashlib.sha256(python_realpath.read_bytes()).hexdigest()
    python_version = platform.python_version()
    scheduler_submission = {
        "sbatch_parsable": f"{job_id};{cluster}",
        "job_id": job_id,
        "cluster": cluster,
        "job_name": job_name,
        "user": job_user,
        "workdir": str(ROOT),
    }
    pending = {
        "schema": contract.SUBMISSION_SCHEMA,
        "status": "submitted_pending_nondecisive",
        "decisive": False,
        "authoritative": False,
        "revision": revision,
        "published_ref": "local-e2e-committed-clone",
        "remote_host": "linux-e2e",
        "remote_namespace": {
            "id": namespace_id,
            "path": str(ROOT),
            "device": namespace_stat.st_dev,
            "inode": namespace_stat.st_ino,
            "results_path": str(results),
            "results_device": results_stat.st_dev,
            "results_inode": results_stat.st_ino,
        },
        "attempt_id": attempt_id,
        "submission_nonce": nonce,
        "dependency": None,
        "job_id": job_id,
        "scheduler_submission": scheduler_submission,
        "expected_marker_name": f"component-quotient-census-{job_id}.current",
        "contract": {
            "expected_sources": contract.EXPECTED_SOURCES,
            "manifest_relative_path": contract.MANIFEST_RELATIVE_PATH,
            "lock_sha256": contract.LOCK_SHA256,
            "manifest_sha256": contract.MANIFEST_SHA256,
            "portable_source_set_sha256": contract.PORTABLE_SOURCE_SET_SHA256,
        },
        "python": {
            "realpath": str(python_realpath),
            "version": python_version,
            "sha256": python_sha256,
        },
    }
    pending["receipt_sha256"] = hashlib.sha256(
        contract.canonical_json_bytes(pending)
    ).hexdigest()
    pending_path = results / (
        f"component-quotient-census-submission-{attempt_id}-{job_id}.json"
    )
    _write_immutable(pending_path, contract.canonical_json_bytes(pending))

    _, census_aggregate, _ = census.run_census(
        manifest,
        records,
        aggregate,
        targets,
        repository_root=ROOT,
        lock_path=ROOT / contract.LOCK_RELATIVE_PATH,
        require_exact_contract=True,
    )
    if census_aggregate["gates"]["validity"]["pass"] is not True:
        raise SystemExit("real 7,503-row census did not pass validity")
    _write_immutable(
        analyzer_log,
        (
            f"sources=7503 validity=true manifest_sha256={contract.MANIFEST_SHA256}\n"
        ).encode("ascii"),
    )
    snapshot = independent.capture_snapshot(
        repository_root=ROOT,
        lock_path=ROOT / contract.LOCK_RELATIVE_PATH,
        manifest_path=manifest,
        records_path=records,
        aggregate_path=aggregate,
        targets_path=targets,
        expected_manifest_sha256=contract.MANIFEST_SHA256,
    )
    decision = independent.verify_snapshot(snapshot)
    if decision.get("decisive") is not True or decision.get("validity_pass") is not True:
        raise SystemExit("real independent semantic verification was not decisive")
    _write_immutable(verification, contract.canonical_json_bytes(decision))
    _write_immutable(
        verifier_log,
        (
            f"decisive=true receipt_sha256={decision['receipt_sha256']}\n"
        ).encode("ascii"),
    )

    os.environ.update(
        {
            "SLURM_JOB_ID": str(job_id),
            "SLURM_CLUSTER_NAME": cluster,
            "SLURM_JOB_NAME": job_name,
            "SLURM_JOB_USER": job_user,
            "SLURM_SUBMIT_DIR": str(ROOT),
        }
    )
    bundle_name = f"component-quotient-census-{job_id}-attempt-{attempt_id}.tar"
    finalizer.publish_verified_bundle(
        final_bundle=results / bundle_name,
        current_marker=results / f"component-quotient-census-{job_id}.current",
        attempt_id=attempt_id,
        submission_nonce=nonce,
        namespace_root=ROOT,
        namespace_id=namespace_id,
        namespace_device=namespace_stat.st_dev,
        namespace_inode=namespace_stat.st_ino,
        results_device=results_stat.st_dev,
        results_inode=results_stat.st_ino,
        repository_root=ROOT,
        manifest_path=manifest,
        expected_manifest_sha256=contract.MANIFEST_SHA256,
        lock_path=ROOT / contract.LOCK_RELATIVE_PATH,
        records_path=records,
        aggregate_path=aggregate,
        targets_path=targets,
        verification_path=verification,
        run_log_path=analyzer_log,
        verification_log_path=verifier_log,
        revision=revision,
        job_id=job_id,
        sbatch_parsable=f"{job_id};{cluster}",
        slurm_cluster=cluster,
        job_name=job_name,
        job_user=job_user,
        workdir=ROOT,
        python_realpath=python_realpath,
        python_version=python_version,
        python_sha256=python_sha256,
    )
    evidence = consumer.SchedulerEvidence(
        job_id,
        f"{cluster}:{job_id}",
        cluster,
        "2026-07-15T12:00:00",
        job_name,
        job_user,
        str(ROOT),
        "COMPLETED",
        "0:0",
    )
    published = consumer.verify_publication(
        submission_receipt=pending_path,
        repository_root=ROOT,
        consumer_attempt_id="e2e7503consumer01",
        scheduler_query=lambda selected_job, selected_cluster: evidence,
    )
    receipt = json.loads((results / published.name).read_text(encoding="ascii"))
    if (
        receipt["scheduler"]["sluid"] != evidence.sluid
        or receipt["scheduler_submission"] != scheduler_submission
        or receipt["bundle_metadata"]["runtime_environment"]["publication"]["method"]
        != "proc_self_fd_linkat_at_symlink_follow"
        or receipt["independent_decision"]["independent_projection_oracle"]["passed"]
        is not True
    ):
        raise SystemExit("end-to-end consumer receipt lost a required binding")
    mode = stat.S_IMODE((results / published.name).stat().st_mode)
    if mode != 0o444 or (results / published.name).stat().st_nlink != 1:
        raise SystemExit("end-to-end consumer receipt is not one immutable inode")
    print(
        json.dumps(
            {
                "manifest_rows": len(rows),
                "manifest_sha256": contract.MANIFEST_SHA256,
                "receipt": published.name,
                "receipt_sha256": published.sha256,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
