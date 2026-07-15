#!/usr/bin/env python3
"""Validate and persist a held T5 submission receipt before remote release."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import component_quotient_contract as contract
from scripts.bench import verify_component_quotient_publication as consumer


class SubmissionHandoffError(ValueError):
    """The local held-job handoff failed closed."""


@dataclass(frozen=True)
class ExpectedSubmission:
    revision: str
    published_ref: str
    remote_host: str
    namespace_path: str
    namespace_id: str
    namespace_device: int
    namespace_inode: int
    results_device: int
    results_inode: int
    attempt_id: str
    submission_nonce: str
    dependency: int | None
    job_id: int
    cluster: str
    job_name: str
    job_user: str
    held_receipt_sha256: str
    python_realpath: str
    python_version: str
    python_sha256: str


def _require_expected(
    receipt: dict[str, object], expected: ExpectedSubmission
) -> None:
    scheduler = receipt.get("scheduler_submission")
    namespace = receipt.get("remote_namespace")
    python = receipt.get("python")
    held = receipt.get("scheduler_held")
    if (
        type(scheduler) is not dict
        or type(namespace) is not dict
        or type(python) is not dict
        or type(held) is not dict
    ):
        raise SubmissionHandoffError(
            "pending receipt lacks scheduler, namespace, or Python binding"
        )
    observed = (
        receipt.get("revision"),
        receipt.get("published_ref"),
        receipt.get("remote_host"),
        namespace.get("id"),
        namespace.get("path"),
        namespace.get("device"),
        namespace.get("inode"),
        namespace.get("results_path"),
        namespace.get("results_device"),
        namespace.get("results_inode"),
        receipt.get("attempt_id"),
        receipt.get("submission_nonce"),
        receipt.get("dependency"),
        receipt.get("job_id"),
        scheduler.get("cluster"),
        scheduler.get("sbatch_parsable"),
        scheduler.get("job_name"),
        scheduler.get("user"),
        scheduler.get("workdir"),
        held.get("receipt_sha256"),
        python.get("realpath"),
        python.get("version"),
        python.get("sha256"),
    )
    required = (
        expected.revision,
        expected.published_ref,
        expected.remote_host,
        expected.namespace_id,
        expected.namespace_path,
        expected.namespace_device,
        expected.namespace_inode,
        f"{expected.namespace_path}/results",
        expected.results_device,
        expected.results_inode,
        expected.attempt_id,
        expected.submission_nonce,
        expected.dependency,
        expected.job_id,
        expected.cluster,
        f"{expected.job_id};{expected.cluster}",
        expected.job_name,
        expected.job_user,
        expected.namespace_path,
        expected.held_receipt_sha256,
        expected.python_realpath,
        expected.python_version,
        expected.python_sha256,
    )
    if observed != required:
        raise SubmissionHandoffError("pending receipt differs from the local submission handoff")


def persist_pending_receipt_no_replace(
    path: Path, payload: bytes, expected: ExpectedSubmission
) -> dict[str, object]:
    """Parse first, then create and fsync one immutable local receipt inode."""

    try:
        receipt = consumer.validate_pending_submission_bytes(payload)
        _require_expected(receipt, expected)
    except (consumer.ConsumerVerificationError, contract.ContractError) as error:
        raise SubmissionHandoffError(str(error)) from error

    path = Path(os.path.abspath(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise SubmissionHandoffError(
            f"cannot create unique local pending receipt {path}: {error}"
        ) from error
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise SubmissionHandoffError(
                    "local pending receipt write made no progress"
                )
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        descriptor_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(descriptor_stat.st_mode)
            or descriptor_stat.st_nlink != 1
            or stat.S_IMODE(descriptor_stat.st_mode) != 0o444
            or descriptor_stat.st_size != len(payload)
        ):
            raise SubmissionHandoffError(
                "local pending receipt inode identity changed during persistence"
            )
    except OSError as error:
        raise SubmissionHandoffError(
            f"cannot persist local pending receipt {path}: {error}"
        ) from error
    finally:
        os.close(descriptor)

    directory = os.open(
        path.parent,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory)
    except OSError as error:
        raise SubmissionHandoffError(
            f"cannot fsync local pending receipt directory: {error}"
        ) from error
    finally:
        os.close(directory)

    try:
        persisted = consumer.read_pending_submission(path)
        _require_expected(persisted, expected)
    except (consumer.ConsumerVerificationError, contract.ContractError) as error:
        raise SubmissionHandoffError(
            f"persisted local pending receipt failed revalidation: {error}"
        ) from error
    return persisted


def guarded_handoff(
    *,
    path: Path,
    payload: bytes,
    expected: ExpectedSubmission,
    release: Callable[[], None],
    cancel: Callable[[], None],
) -> dict[str, object]:
    """Cancel on every local failure and never release before persistence."""

    released = False
    try:
        receipt = persist_pending_receipt_no_replace(path, payload, expected)
        release()
        released = True
        return receipt
    except BaseException as handoff_error:
        if not released:
            try:
                cancel()
            except BaseException as cancel_error:
                raise SubmissionHandoffError(
                    f"held-job handoff failed ({handoff_error}); cancellation also failed: "
                    f"{cancel_error}"
                ) from handoff_error
        raise


_REMOTE_CONTROL = b"""set -euo pipefail
action="$1"
work="$2"
attempt_id="$3"
expected_receipt_sha256="$4"
python_realpath="$5"
python_sha256="$6"
if [[ "$work" != /* ]] || [[ "$work" == *[[:space:]]* ]] || \\
   [[ ! "$attempt_id" =~ ^[A-Za-z0-9_.-]+$ ]] || \\
   [[ ! "$expected_receipt_sha256" =~ ^[0-9a-f]{64}$ ]] || \\
   [[ "$python_realpath" != /* ]] || [[ "$python_realpath" == *[[:space:]]* ]] || \\
   [[ ! "$python_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "held-job identity is malformed" >&2
  exit 2
fi
if [ "$action" != release ] && [ "$action" != cancel ]; then
  echo "unsupported held-job operation" >&2
  exit 2
fi
if [ "$(cd -- "$work" && pwd -P)" != "$work" ]; then
  echo "held-job workdir is not canonical" >&2
  exit 2
fi
observed_python_sha256="$(sha256sum -- "$python_realpath")"
observed_python_sha256="${observed_python_sha256%% *}"
if [ "$observed_python_sha256" != "$python_sha256" ]; then
  echo "held-job Python identity drift" >&2
  exit 2
fi
receipt="$work/results/component-quotient-census-held-${attempt_id}.json"
exec env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C TZ=UTC \\
  "$python_realpath" -I -B -S "$work/scripts/bench/t5_held_scheduler.py" operate \\
    --receipt "$receipt" \\
    --expected-receipt-sha256 "$expected_receipt_sha256" \\
    --expected-job-id "$7" \\
    --expected-cluster "$8" \\
    --expected-job-name "$9" \\
    --expected-user "${10}" \\
    --expected-workdir "$work" \\
    --action "$action"
"""


def _remote_operation(
    ssh: Path, remote_host: str, action: str, expected: ExpectedSubmission
) -> None:
    if (
        not ssh.is_absolute()
        or not ssh.is_file()
        or not os.access(ssh, os.X_OK)
        or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.@-" for character in remote_host)
    ):
        raise SubmissionHandoffError("SSH executable or remote host is malformed")
    try:
        subprocess.run(
            [
                str(ssh),
                remote_host,
                "bash",
                "-s",
                "--",
                action,
                expected.namespace_path,
                expected.attempt_id,
                expected.held_receipt_sha256,
                expected.python_realpath,
                expected.python_sha256,
                str(expected.job_id),
                expected.cluster,
                expected.job_name,
                expected.job_user,
            ],
            input=_REMOTE_CONTROL,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
            },
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SubmissionHandoffError(
            f"remote held-job {action} operation failed: {error}"
        ) from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--published-ref", required=True)
    parser.add_argument("--remote-host", required=True)
    parser.add_argument("--namespace-path", required=True)
    parser.add_argument("--namespace-id", required=True)
    parser.add_argument("--namespace-device", type=int, required=True)
    parser.add_argument("--namespace-inode", type=int, required=True)
    parser.add_argument("--results-device", type=int, required=True)
    parser.add_argument("--results-inode", type=int, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--submission-nonce", required=True)
    parser.add_argument("--dependency", required=True)
    parser.add_argument("--job-id", type=int, required=True)
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--job-name", required=True)
    parser.add_argument("--job-user", required=True)
    parser.add_argument("--held-receipt-sha256", required=True)
    parser.add_argument("--python-realpath", required=True)
    parser.add_argument("--python-version", required=True)
    parser.add_argument("--python-sha256", required=True)
    parser.add_argument("--ssh", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.dependency and (
        not arguments.dependency.isdecimal() or int(arguments.dependency) < 1
    ):
        print("held T5 submission dependency is malformed", file=sys.stderr)
        return 2
    expected = ExpectedSubmission(
        revision=arguments.revision,
        published_ref=arguments.published_ref,
        remote_host=arguments.remote_host,
        namespace_path=arguments.namespace_path,
        namespace_id=arguments.namespace_id,
        namespace_device=arguments.namespace_device,
        namespace_inode=arguments.namespace_inode,
        results_device=arguments.results_device,
        results_inode=arguments.results_inode,
        attempt_id=arguments.attempt_id,
        submission_nonce=arguments.submission_nonce,
        dependency=int(arguments.dependency) if arguments.dependency else None,
        job_id=arguments.job_id,
        cluster=arguments.cluster,
        job_name=arguments.job_name,
        job_user=arguments.job_user,
        held_receipt_sha256=arguments.held_receipt_sha256,
        python_realpath=arguments.python_realpath,
        python_version=arguments.python_version,
        python_sha256=arguments.python_sha256,
    )
    payload = sys.stdin.buffer.read(128 * 1024 + 1)
    try:
        receipt = guarded_handoff(
            path=arguments.receipt,
            payload=payload,
            expected=expected,
            release=lambda: _remote_operation(
                arguments.ssh, arguments.remote_host, "release", expected
            ),
            cancel=lambda: _remote_operation(
                arguments.ssh, arguments.remote_host, "cancel", expected
            ),
        )
    except (OSError, SubmissionHandoffError, consumer.ConsumerVerificationError) as error:
        print(f"held T5 submission handoff failed: {error}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "cluster": expected.cluster,
                "job_id": expected.job_id,
                "receipt": str(Path(os.path.abspath(arguments.receipt))),
                "receipt_sha256": receipt["receipt_sha256"],
                "released_after_local_persist": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
