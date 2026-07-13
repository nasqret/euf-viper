#!/usr/bin/env python3
"""Emit WMI completion metadata only for the exact verified census bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bench import census_component_quotient_ram as census  # noqa: E402


METADATA_SCHEMA = "euf-viper.component-quotient-ram-wmi-run.v1"
EXPECTED_RECEIPT_KEYS = {
    "schema",
    "verified",
    "campaign_id",
    "interpretation",
    "sources",
    "targets",
    "validity_pass",
    "implementation_allowed",
    "decoder_oracle_sha256",
    "hashes",
}
AGGREGATE_HASH_KEYS = {
    "lock_sha256",
    "input_manifest_sha256",
    "portable_source_set_sha256",
    "analyzer_sha256",
    "parser_sha256",
    "taxonomy_builder_sha256",
    "records_jsonl_sha256",
    "terminal_record_sha256",
    "derived_target_manifest_sha256",
}
RECEIPT_HASH_KEYS = AGGREGATE_HASH_KEYS | {
    "aggregate_json_sha256",
    "recomputed_gates_sha256",
}


class MetadataFinalizationError(ValueError):
    """Raised when completion metadata cannot be bound to verified bytes."""


@dataclass(frozen=True)
class Snapshot:
    path: Path
    payload: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


def _is_lower_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _read_snapshot(path: Path, context: str) -> Snapshot:
    resolved = Path(path).resolve(strict=False)
    try:
        payload = resolved.read_bytes()
    except OSError as error:
        raise MetadataFinalizationError(
            f"cannot read {context} {resolved}: {error}"
        ) from error
    return Snapshot(resolved, payload)


def _strict_canonical_json(payload: bytes, context: str) -> dict[str, object]:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise MetadataFinalizationError(f"{context} must be ASCII") from error
    try:
        value = census.family_manifest.strict_json_loads(text)
    except (json.JSONDecodeError, ValueError) as error:
        raise MetadataFinalizationError(f"malformed {context}: {error}") from error
    if type(value) is not dict:
        raise MetadataFinalizationError(f"{context} must be a JSON object")
    if census.canonical_json_bytes(value) != payload:
        raise MetadataFinalizationError(f"{context} must be canonical JSON")
    return value


def _strict_canonical_jsonl(payload: bytes, context: str) -> list[dict[str, object]]:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise MetadataFinalizationError(f"{context} must be ASCII") from error
    if payload and not text.endswith("\n"):
        raise MetadataFinalizationError(f"{context} ends with a partial line")
    rows: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            raise MetadataFinalizationError(
                f"{context} line {line_number} is blank"
            )
        try:
            value = census.family_manifest.strict_json_loads(line)
        except (json.JSONDecodeError, ValueError) as error:
            raise MetadataFinalizationError(
                f"{context} line {line_number} is malformed: {error}"
            ) from error
        if type(value) is not dict:
            raise MetadataFinalizationError(
                f"{context} line {line_number} must be an object"
            )
        if census.canonical_json_bytes(value).decode("ascii") != line + "\n":
            raise MetadataFinalizationError(
                f"{context} line {line_number} is not canonical JSON"
            )
        rows.append(value)
    return rows


def _validate_receipt(
    receipt: dict[str, object], expected_sources: int
) -> dict[str, str]:
    if set(receipt) != EXPECTED_RECEIPT_KEYS:
        raise MetadataFinalizationError("verification receipt keys differ")
    if (
        receipt["schema"] != census.BUNDLE_VERIFICATION_SCHEMA
        or receipt["verified"] is not True
        or receipt["campaign_id"]
        != "t5-component-quotient-ram-opportunity-census-v1"
        or receipt["interpretation"] != census.INTERPRETATION
        or type(receipt["sources"]) is not int
        or receipt["sources"] != expected_sources
        or type(receipt["targets"]) is not int
        or receipt["targets"] < 0
        or receipt["validity_pass"] is not True
        or type(receipt["implementation_allowed"]) is not bool
        or receipt["decoder_oracle_sha256"]
        != census.DECODER_ORACLE_FROZEN_SHA256
    ):
        raise MetadataFinalizationError(
            "component quotient strict bundle verification did not pass"
        )
    hashes = receipt["hashes"]
    if type(hashes) is not dict or set(hashes) != RECEIPT_HASH_KEYS:
        raise MetadataFinalizationError("verification receipt hash keys differ")
    if any(not _is_lower_sha256(value) for value in hashes.values()):
        raise MetadataFinalizationError(
            "verification receipt contains an invalid SHA-256"
        )
    return hashes  # type: ignore[return-value]


def _capture_python_identity(
    expected_realpath: Path,
    expected_version: str,
    expected_sha256: str,
) -> tuple[dict[str, str], Snapshot]:
    if not expected_realpath.is_absolute():
        raise MetadataFinalizationError("pinned Python realpath must be absolute")
    if not expected_version or not _is_lower_sha256(expected_sha256):
        raise MetadataFinalizationError("pinned Python identity is malformed")
    try:
        resolved = expected_realpath.resolve(strict=True)
        running = Path(sys.executable).resolve(strict=True)
    except OSError as error:
        raise MetadataFinalizationError(
            f"cannot resolve pinned Python executable: {error}"
        ) from error
    if resolved != expected_realpath or running != expected_realpath:
        raise MetadataFinalizationError(
            f"Python realpath drift: expected {expected_realpath}, running {running}"
        )
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise MetadataFinalizationError("pinned Python realpath is not executable")
    if platform.python_version() != expected_version:
        raise MetadataFinalizationError(
            "Python version drift: "
            f"expected {expected_version}, got {platform.python_version()}"
        )
    snapshot = _read_snapshot(resolved, "Python executable")
    if snapshot.sha256 != expected_sha256:
        raise MetadataFinalizationError(
            f"Python SHA-256 drift: expected {expected_sha256}, got {snapshot.sha256}"
        )
    return (
        {
            "realpath": str(resolved),
            "version": expected_version,
            "sha256": expected_sha256,
        },
        snapshot,
    )


def _assert_snapshot_unchanged(snapshot: Snapshot, context: str) -> None:
    current = _read_snapshot(snapshot.path, context)
    if (
        current.sha256 != snapshot.sha256
        or len(current.payload) != len(snapshot.payload)
    ):
        raise MetadataFinalizationError(
            f"{context} changed during metadata finalization"
        )


def finalize_metadata(
    *,
    metadata_out: Path,
    repository_root: Path,
    manifest_path: Path,
    lock_path: Path,
    records_path: Path,
    aggregate_path: Path,
    targets_path: Path,
    verification_path: Path,
    run_log_path: Path,
    verification_log_path: Path,
    expected_sources: int,
    revision: str,
    job_id: int,
    python_realpath: Path,
    python_version: str,
    python_sha256: str,
) -> dict[str, object]:
    if expected_sources < 1:
        raise MetadataFinalizationError("expected source count must be positive")
    if (
        len(revision) != 40
        or any(character not in "0123456789abcdef" for character in revision)
    ):
        raise MetadataFinalizationError("revision must be a full lowercase Git SHA-1")
    if job_id < 1:
        raise MetadataFinalizationError("job id must be positive")

    python_identity, python_snapshot = _capture_python_identity(
        python_realpath, python_version, python_sha256
    )
    lock = census.load_campaign_lock(lock_path)
    if lock.expected_sources != expected_sources:
        raise MetadataFinalizationError(
            "campaign lock and requested source counts differ"
        )
    sources, manifest_bytes, portable_bytes = census.load_manifest(
        manifest_path, repository_root, expected_sources
    )
    if hashlib.sha256(portable_bytes).hexdigest() != lock.portable_source_set_sha256:
        raise MetadataFinalizationError(
            "current portable source commitment differs from campaign lock"
        )

    snapshots = {
        "manifest": Snapshot(Path(manifest_path).resolve(strict=False), manifest_bytes),
        "lock": Snapshot(Path(lock_path).resolve(strict=False), lock.raw_bytes),
        "analyzer": _read_snapshot(Path(census.__file__), "analyzer"),
        "verifier": _read_snapshot(
            ROOT / "scripts/bench/verify_component_quotient_ram_bundle.py",
            "bundle verifier",
        ),
        "metadata_finalizer": _read_snapshot(Path(__file__), "metadata finalizer"),
        "parser": _read_snapshot(census.PARSER_PATH, "independent parser"),
        "taxonomy_builder": _read_snapshot(
            census.TAXONOMY_PATH, "taxonomy builder"
        ),
        "records": _read_snapshot(records_path, "record stream"),
        "aggregate": _read_snapshot(aggregate_path, "aggregate"),
        "targets": _read_snapshot(targets_path, "target manifest"),
        "run": _read_snapshot(run_log_path, "analyzer log"),
        "verification": _read_snapshot(verification_path, "verification receipt"),
        "verification_run": _read_snapshot(
            verification_log_path, "verification log"
        ),
        "python_executable": python_snapshot,
    }
    output_resolved = Path(metadata_out).resolve(strict=False)
    occupied = {snapshot.path for snapshot in snapshots.values()}
    occupied.update(source.source_path for source in sources)
    if output_resolved in occupied:
        raise MetadataFinalizationError("metadata output must not overwrite an input")

    receipt = _strict_canonical_json(
        snapshots["verification"].payload, "verification receipt"
    )
    receipt_hashes = _validate_receipt(receipt, expected_sources)
    records = census.verify_record_stream(
        snapshots["records"].payload, expected_sources, lock
    )
    targets = _strict_canonical_jsonl(
        snapshots["targets"].payload, "target manifest"
    )
    aggregate = _strict_canonical_json(
        snapshots["aggregate"].payload, "aggregate"
    )
    gates = aggregate.get("gates")
    aggregate_hashes = aggregate.get("hashes")
    if type(gates) is not dict or type(aggregate_hashes) is not dict:
        raise MetadataFinalizationError("aggregate gates or hashes are malformed")
    validity = gates.get("validity")
    if type(validity) is not dict or type(validity.get("pass")) is not bool:
        raise MetadataFinalizationError("aggregate validity gate is malformed")
    if type(gates.get("implementation_allowed")) is not bool:
        raise MetadataFinalizationError(
            "aggregate implementation gate is malformed"
        )

    terminal_record_sha256 = (
        records[-1].get("record_sha256") if records else None
    )
    if not _is_lower_sha256(terminal_record_sha256):
        raise MetadataFinalizationError("record stream terminal hash is malformed")
    current_hashes = {
        "lock_sha256": snapshots["lock"].sha256,
        "input_manifest_sha256": snapshots["manifest"].sha256,
        "portable_source_set_sha256": hashlib.sha256(portable_bytes).hexdigest(),
        "analyzer_sha256": snapshots["analyzer"].sha256,
        "parser_sha256": snapshots["parser"].sha256,
        "taxonomy_builder_sha256": snapshots["taxonomy_builder"].sha256,
        "records_jsonl_sha256": snapshots["records"].sha256,
        "terminal_record_sha256": terminal_record_sha256,
        "derived_target_manifest_sha256": snapshots["targets"].sha256,
        "aggregate_json_sha256": snapshots["aggregate"].sha256,
        "recomputed_gates_sha256": hashlib.sha256(
            census.canonical_json_bytes(gates)
        ).hexdigest(),
    }
    if set(current_hashes) != RECEIPT_HASH_KEYS:
        raise MetadataFinalizationError("recomputed receipt hash keys differ")
    if set(aggregate_hashes) != AGGREGATE_HASH_KEYS:
        raise MetadataFinalizationError("aggregate receipt-bound hash keys differ")
    for key in sorted(AGGREGATE_HASH_KEYS):
        if aggregate_hashes[key] != current_hashes[key]:
            raise MetadataFinalizationError(
                f"aggregate hash mismatch for {key}: "
                f"expected {aggregate_hashes[key]}, got {current_hashes[key]}"
            )
    for key in sorted(RECEIPT_HASH_KEYS):
        if receipt_hashes[key] != current_hashes[key]:
            raise MetadataFinalizationError(
                f"verification receipt hash mismatch for {key}: "
                f"expected {receipt_hashes[key]}, got {current_hashes[key]}"
            )
    if (
        receipt["campaign_id"] != lock.campaign_id
        or receipt["sources"] != len(records)
        or receipt["targets"] != len(targets)
        or receipt["validity_pass"] is not validity["pass"]
        or receipt["implementation_allowed"]
        is not gates["implementation_allowed"]
        or receipt["decoder_oracle_sha256"] != lock.decoder_oracle_sha256
    ):
        raise MetadataFinalizationError(
            "verification receipt and captured aggregate/lock relations differ"
        )

    payload: dict[str, object] = {
        "schema": METADATA_SCHEMA,
        "status": "completed",
        "revision": revision,
        "job_id": job_id,
        "hostname": platform.node(),
        "python": python_identity,
        "validation": {
            "expected_sources": expected_sources,
            "observed_sources": receipt["sources"],
            "targets": receipt["targets"],
            "validity_pass": receipt["validity_pass"],
            "decoder_oracle_sha256": receipt["decoder_oracle_sha256"],
            "implementation_allowed": receipt["implementation_allowed"],
            "verification_receipt_sha256": snapshots["verification"].sha256,
            "receipt_bound_hashes": current_hashes,
        },
        "artifacts": {
            name: {"path": str(snapshot.path), "sha256": snapshot.sha256}
            for name, snapshot in sorted(snapshots.items())
        },
    }

    for source in sources:
        current = _read_snapshot(source.source_path, source.relative_path)
        if (
            current.sha256 != source.source_sha256
            or len(current.payload) != len(source.source_bytes)
        ):
            raise MetadataFinalizationError(
                f"source changed during metadata finalization: {source.relative_path}"
            )
    for name, snapshot in sorted(snapshots.items()):
        _assert_snapshot_unchanged(snapshot, name)

    metadata_bytes = (
        json.dumps(payload, indent=2, sort_keys=True).encode("ascii") + b"\n"
    )
    census._atomic_write(((metadata_out, metadata_bytes),))
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata-out", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--aggregate", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--verification", type=Path, required=True)
    parser.add_argument("--run-log", type=Path, required=True)
    parser.add_argument("--verification-log", type=Path, required=True)
    parser.add_argument("--expected-sources", type=int, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--job-id", type=int, required=True)
    parser.add_argument("--python-realpath", type=Path, required=True)
    parser.add_argument("--python-version", required=True)
    parser.add_argument("--python-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = finalize_metadata(
            metadata_out=args.metadata_out,
            repository_root=args.repository_root,
            manifest_path=args.manifest,
            lock_path=args.lock,
            records_path=args.records,
            aggregate_path=args.aggregate,
            targets_path=args.targets,
            verification_path=args.verification,
            run_log_path=args.run_log,
            verification_log_path=args.verification_log,
            expected_sources=args.expected_sources,
            revision=args.revision,
            job_id=args.job_id,
            python_realpath=args.python_realpath,
            python_version=args.python_version,
            python_sha256=args.python_sha256,
        )
    except (census.CensusError, MetadataFinalizationError) as error:
        raise SystemExit(f"component quotient metadata finalization failed: {error}")
    print(
        f"status={payload['status']} "
        f"receipt_sha256={payload['validation']['verification_receipt_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
