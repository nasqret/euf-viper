#!/usr/bin/env python3
"""Capture and revalidate one held Slurm job before release or cancellation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import component_quotient_contract as contract  # noqa: E402


HELD_SCHEMA = "euf-viper.component-quotient-held-scheduler.v1"
SACCT_FORMAT = (
    "JobIDRaw%64,SLUID%256,Cluster%128,Submit%32,JobName%128,User%128,"
    "WorkDir%4096,State%64"
)


class HeldSchedulerError(ValueError):
    """The held scheduler identity is missing, ambiguous, or changed."""


@dataclass(frozen=True)
class HeldSchedulerIdentity:
    job_id: int
    sluid: str
    cluster: str
    submit_time: str
    job_name: str
    user: str
    workdir: str
    state: str
    hold_reason: str

    def to_json(self) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": HELD_SCHEMA,
            "job_id": self.job_id,
            "sluid": self.sluid,
            "cluster": self.cluster,
            "submit_time": self.submit_time,
            "job_name": self.job_name,
            "user": self.user,
            "workdir": self.workdir,
            "state": self.state,
            "hold_reason": self.hold_reason,
        }
        value["receipt_sha256"] = hashlib.sha256(
            contract.canonical_json_bytes(value)
        ).hexdigest()
        return value


def _safe_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }


def _run(arguments: list[str]) -> str:
    try:
        completed = subprocess.run(
            arguments,
            env=_safe_environment(),
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise HeldSchedulerError(
            f"scheduler query failed for {arguments[0]}: {error}"
        ) from error
    return completed.stdout


def _require_identity(identity: HeldSchedulerIdentity) -> HeldSchedulerIdentity:
    if type(identity) is not HeldSchedulerIdentity or type(identity.job_id) is not int:
        raise HeldSchedulerError("held scheduler identity type drift")
    if identity.job_id < 1:
        raise HeldSchedulerError("held scheduler job id is malformed")
    strings = (
        identity.sluid,
        identity.cluster,
        identity.submit_time,
        identity.job_name,
        identity.user,
        identity.workdir,
        identity.state,
        identity.hold_reason,
    )
    if any(
        type(value) is not str
        or not value
        or len(value) > 4096
        or any(character in value for character in "\x00\r\n|")
        for value in strings
    ):
        raise HeldSchedulerError("held scheduler identity text is malformed")
    try:
        contract.require_safe_token(identity.cluster, "held scheduler cluster")
        contract.require_safe_token(identity.job_name, "held scheduler job name")
        contract.require_safe_token(identity.user, "held scheduler user")
    except contract.ContractError as error:
        raise HeldSchedulerError(str(error)) from error
    if (
        not os.path.isabs(identity.workdir)
        or identity.sluid == str(identity.job_id)
        or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}",
            identity.submit_time,
        )
        or identity.state != "PENDING"
        or identity.hold_reason != "JobHeldUser"
    ):
        raise HeldSchedulerError("job is not the exact user-held allocation")
    return identity


def validate_held_receipt(value: object) -> HeldSchedulerIdentity:
    fields = {
        "schema",
        "job_id",
        "sluid",
        "cluster",
        "submit_time",
        "job_name",
        "user",
        "workdir",
        "state",
        "hold_reason",
        "receipt_sha256",
    }
    if type(value) is not dict or set(value) != fields or value["schema"] != HELD_SCHEMA:
        raise HeldSchedulerError("held scheduler receipt field set drift")
    stored = value["receipt_sha256"]
    unhashed = dict(value)
    unhashed.pop("receipt_sha256")
    if stored != hashlib.sha256(contract.canonical_json_bytes(unhashed)).hexdigest():
        raise HeldSchedulerError("held scheduler receipt self-digest mismatch")
    try:
        identity = HeldSchedulerIdentity(
            job_id=value["job_id"],
            sluid=value["sluid"],
            cluster=value["cluster"],
            submit_time=value["submit_time"],
            job_name=value["job_name"],
            user=value["user"],
            workdir=value["workdir"],
            state=value["state"],
            hold_reason=value["hold_reason"],
        )
    except TypeError as error:
        raise HeldSchedulerError("held scheduler receipt types drifted") from error
    return _require_identity(identity)


def held_receipt_bytes(identity: HeldSchedulerIdentity) -> bytes:
    return contract.canonical_json_bytes(_require_identity(identity).to_json())


def parse_held_receipt_bytes(payload: bytes) -> HeldSchedulerIdentity:
    if type(payload) is not bytes or not 1 <= len(payload) <= 128 * 1024:
        raise HeldSchedulerError("held scheduler receipt byte bound drift")
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HeldSchedulerError(f"held scheduler receipt is not ASCII JSON: {error}") from error
    if contract.canonical_json_bytes(value) != payload:
        raise HeldSchedulerError("held scheduler receipt is not canonical JSON")
    return validate_held_receipt(value)


def read_held_receipt(path: Path) -> HeldSchedulerIdentity:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HeldSchedulerError(f"cannot open held scheduler receipt: {error}") from error
    try:
        identity = os.fstat(descriptor)
        if (
            not stat.S_ISREG(identity.st_mode)
            or identity.st_nlink != 1
            or stat.S_IMODE(identity.st_mode) != 0o444
            or not 1 <= identity.st_size <= 128 * 1024
        ):
            raise HeldSchedulerError("held scheduler receipt inode is not immutable")
        payload = bytearray()
        while len(payload) <= 128 * 1024:
            chunk = os.read(descriptor, min(65536, 128 * 1024 + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
            (identity.st_dev, identity.st_ino, identity.st_size, identity.st_mode)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mode)
        ):
            raise HeldSchedulerError("held scheduler receipt changed during read")
    finally:
        os.close(descriptor)
    return parse_held_receipt_bytes(bytes(payload))


def persist_held_receipt_no_replace(path: Path, identity: HeldSchedulerIdentity) -> bytes:
    payload = held_receipt_bytes(identity)
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
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise HeldSchedulerError("held scheduler receipt write made no progress")
                offset += written
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
    except OSError as error:
        raise HeldSchedulerError(f"cannot persist held scheduler receipt: {error}") from error
    if read_held_receipt(path) != identity:
        raise HeldSchedulerError("persisted held scheduler receipt revalidation drift")
    return payload


def _parse_scontrol_job(output: str, job_id: int) -> dict[str, str]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        raise HeldSchedulerError("scontrol returned no unique job row")
    fields: dict[str, str] = {}
    try:
        tokens = shlex.split(lines[0], posix=True)
    except ValueError as error:
        raise HeldSchedulerError(f"scontrol row cannot be parsed: {error}") from error
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key in fields:
            raise HeldSchedulerError(f"scontrol duplicated field {key}")
        fields[key] = value
    required = {"JobId", "JobName", "UserId", "JobState", "Reason", "WorkDir", "SubmitTime"}
    if not required.issubset(fields) or fields["JobId"] != str(job_id):
        raise HeldSchedulerError("scontrol job identity is incomplete")
    return fields


def _parse_sacct_root(output: str, job_id: int) -> tuple[str, ...]:
    rows: list[tuple[str, ...]] = []
    for line in output.splitlines():
        fields = line.strip().split("|")
        if len(fields) == 9 and fields[-1] == "":
            fields.pop()
        if fields and any(fields):
            if len(fields) != 8:
                raise HeldSchedulerError("sacct returned a malformed held-job row")
            if fields[0] == str(job_id):
                rows.append(tuple(fields[1:]))
            else:
                raise HeldSchedulerError("sacct returned a non-root or unrelated row")
    if len(rows) != 1:
        raise HeldSchedulerError("sacct returned no unique root-allocation row")
    return rows[0]


def query_held_job(job_id: int, cluster: str) -> HeldSchedulerIdentity:
    if type(job_id) is not int or job_id < 1:
        raise HeldSchedulerError("held scheduler query job id is malformed")
    try:
        contract.require_safe_token(cluster, "held scheduler query cluster")
    except contract.ContractError as error:
        raise HeldSchedulerError(str(error)) from error
    control = _parse_scontrol_job(
        _run(
            [
                "scontrol",
                f"--clusters={cluster}",
                "show",
                "job",
                str(job_id),
                "--oneliner",
            ]
        ),
        job_id,
    )
    sluid, accounting_cluster, submit, name, user, workdir, state = _parse_sacct_root(
        _run(
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
            ]
        ),
        job_id,
    )
    control_user = control["UserId"].split("(", 1)[0]
    observed = HeldSchedulerIdentity(
        job_id=job_id,
        sluid=sluid,
        cluster=accounting_cluster,
        submit_time=submit,
        job_name=name,
        user=user,
        workdir=workdir,
        state=state,
        hold_reason=control["Reason"],
    )
    _require_identity(observed)
    if (
        accounting_cluster != cluster
        or control["JobName"] != name
        or control_user != user
        or control["WorkDir"] != workdir
        or control["SubmitTime"] != submit
        or control["JobState"] != state
    ):
        raise HeldSchedulerError("scontrol and sacct held identities disagree")
    return observed


def capture_held_job(
    *,
    job_id: int,
    cluster: str,
    job_name: str,
    user: str,
    workdir: str,
    attempts: int = 30,
) -> HeldSchedulerIdentity:
    last_error: HeldSchedulerError | None = None
    for attempt in range(attempts):
        try:
            observed = query_held_job(job_id, cluster)
            expected = (job_id, cluster, job_name, user, workdir)
            actual = (
                observed.job_id,
                observed.cluster,
                observed.job_name,
                observed.user,
                observed.workdir,
            )
            if actual != expected:
                raise HeldSchedulerError("held job differs from pre-submission ownership")
            return observed
        except HeldSchedulerError as error:
            last_error = error
            if attempt + 1 < attempts:
                time.sleep(1)
    raise HeldSchedulerError(f"cannot capture unique held scheduler identity: {last_error}")


def operate_on_held_job(
    identity: HeldSchedulerIdentity, action: str
) -> HeldSchedulerIdentity:
    expected = _require_identity(identity)
    observed = query_held_job(expected.job_id, expected.cluster)
    if observed != expected:
        raise HeldSchedulerError("held scheduler identity changed before operation")
    if action not in {"release", "cancel"}:
        raise HeldSchedulerError("held scheduler operation is unsupported")
    command = (
        ["scontrol", f"--clusters={expected.cluster}", "--quiet", "release", str(expected.job_id)]
        if action == "release"
        else ["scancel", f"--clusters={expected.cluster}", str(expected.job_id)]
    )
    _run(command)
    return expected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture")
    capture.add_argument("--job-id", type=int, required=True)
    capture.add_argument("--cluster", required=True)
    capture.add_argument("--job-name", required=True)
    capture.add_argument("--user", required=True)
    capture.add_argument("--workdir", required=True)
    capture.add_argument("--output", type=Path, required=True)
    operate = commands.add_parser("operate")
    operate.add_argument("--receipt", type=Path, required=True)
    operate.add_argument("--expected-receipt-sha256")
    operate.add_argument("--expected-job-id", type=int)
    operate.add_argument("--expected-cluster", required=True)
    operate.add_argument("--expected-job-name", required=True)
    operate.add_argument("--expected-user", required=True)
    operate.add_argument("--expected-workdir", required=True)
    operate.add_argument("--action", choices=("release", "cancel"), required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "capture":
            identity = capture_held_job(
                job_id=arguments.job_id,
                cluster=arguments.cluster,
                job_name=arguments.job_name,
                user=arguments.user,
                workdir=arguments.workdir,
            )
            payload = persist_held_receipt_no_replace(arguments.output, identity)
            sys.stdout.buffer.write(payload)
        else:
            identity = read_held_receipt(arguments.receipt)
            if arguments.expected_receipt_sha256 is not None:
                contract.require_lower_sha256(
                    arguments.expected_receipt_sha256,
                    "expected held scheduler receipt digest",
                )
            expected_core = (
                arguments.expected_job_id,
                arguments.expected_cluster,
                arguments.expected_job_name,
                arguments.expected_user,
                arguments.expected_workdir,
            )
            observed_core = (
                identity.job_id if arguments.expected_job_id is not None else None,
                identity.cluster,
                identity.job_name,
                identity.user,
                identity.workdir,
            )
            if observed_core != expected_core:
                raise HeldSchedulerError("remote held receipt differs from prebound ownership")
            if (
                arguments.expected_receipt_sha256 is not None
                and identity.to_json()["receipt_sha256"]
                != arguments.expected_receipt_sha256
            ):
                raise HeldSchedulerError("remote held receipt differs from local binding")
            operate_on_held_job(identity, arguments.action)
            print(
                json.dumps(
                    {
                        "action": arguments.action,
                        "cluster": identity.cluster,
                        "job_id": identity.job_id,
                        "revalidated": True,
                    },
                    sort_keys=True,
                )
            )
        return 0
    except (OSError, contract.ContractError, HeldSchedulerError) as error:
        print(f"held scheduler operation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
