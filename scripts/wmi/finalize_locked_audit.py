#!/usr/bin/env python3
"""Publish a descriptor-bound, no-replace index for locked campaign analyses."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
CERT_DIR = ROOT / "scripts" / "cert"
if str(CERT_DIR) not in sys.path:
    sys.path.insert(0, str(CERT_DIR))

from strict_artifacts import (  # noqa: E402
    StrictArtifactError,
    assert_descriptor_path_nofollow,
    atomic_write_nofollow,
    canonical_json_bytes,
    open_read_nofollow,
    read_open_descriptor,
    strict_json_loads,
)


SCHEMA = "euf-viper.locked-p0-audit.v3"


class AuditFinalizeError(ValueError):
    """Raised when an analysis cannot be bound to one immutable index."""


@dataclass
class BoundAnalysis:
    path: Path
    descriptor: int
    raw: bytes
    metadata: os.stat_result
    value: dict[str, Any]


def _open_analysis(path: Path, kind: str, run_root: Path) -> BoundAnalysis:
    try:
        absolute, descriptor = open_read_nofollow(path, f"{kind} global analysis")
        try:
            absolute.relative_to(run_root)
        except ValueError as error:
            os.close(descriptor)
            raise AuditFinalizeError(f"{kind} analysis escapes the run root") from error
        raw, metadata = read_open_descriptor(descriptor, f"{kind} global analysis")
        try:
            value = strict_json_loads(raw.decode("ascii"), f"{kind} global analysis")
        except (UnicodeError, StrictArtifactError) as error:
            os.close(descriptor)
            raise AuditFinalizeError(str(error)) from error
        if type(value) is not dict:
            os.close(descriptor)
            raise AuditFinalizeError(f"{kind} global analysis is not one JSON object")
        return BoundAnalysis(absolute, descriptor, raw, metadata, value)
    except StrictArtifactError as error:
        raise AuditFinalizeError(str(error)) from error


def finalize(
    output: Path,
    provenance: dict[str, Any],
    run_root: Path,
    prepare_job: int,
    shards: int,
    audit_job: int,
    preparation_binding: dict[str, Any],
    *,
    pre_publish_hook: Callable[[], None] | None = None,
) -> dict[str, Any]:
    run_root = run_root.resolve(strict=True)
    bindings = {
        kind: _open_analysis(run_root / "audit" / kind / "global.json", kind, run_root)
        for kind in ("full", "official")
    }
    try:
        payload: dict[str, Any] = {
            "schema": SCHEMA,
            "status": "complete",
            "attempt": provenance["attempt"],
            "analyses": {},
            "environment": provenance["environment"],
            "job_id": audit_job,
            "prepare_job_id": prepare_job,
            "preparation_receipt": preparation_binding,
            "revision": provenance["revision"],
            "run_root": str(run_root),
            "shards": shards,
            "source": {
                "blob_count": provenance["source_blob_count"],
                "blobs_sha256": provenance["source_blobs_sha256"],
                "tree": provenance["source_tree"],
            },
            "submission_manifest_sha256": provenance["manifest_sha256"],
        }
        for kind, binding in bindings.items():
            value = binding.value
            payload["analyses"][kind] = {
                "bytes": len(binding.raw),
                "device": binding.metadata.st_dev,
                "inode": binding.metadata.st_ino,
                "instances": value.get("inputs", {}).get("instances"),
                "path": str(binding.path),
                "promoted": value.get("promoted"),
                "raw_records": value.get("inputs", {}).get("raw_records"),
                "sha256": hashlib.sha256(binding.raw).hexdigest(),
                "shards": len(value.get("inputs", {}).get("shards", [])),
                "status": value.get("status"),
            }

        encoded = canonical_json_bytes(payload)

        def verify_sources() -> None:
            if pre_publish_hook is not None:
                pre_publish_hook()
            for kind, binding in bindings.items():
                assert_descriptor_path_nofollow(
                    binding.path, binding.descriptor, f"{kind} global analysis"
                )
                current, metadata = read_open_descriptor(
                    binding.descriptor, f"{kind} global analysis final rehash"
                )
                if (
                    current != binding.raw
                    or metadata.st_dev != binding.metadata.st_dev
                    or metadata.st_ino != binding.metadata.st_ino
                ):
                    raise StrictArtifactError(
                        f"{kind} global analysis changed before index publication"
                    )

        atomic_write_nofollow(
            output,
            encoded,
            "locked audit index",
            immutable=True,
            mode=0o400,
            pre_publish=verify_sources,
        )
        _, index_fd = open_read_nofollow(output, "locked audit index")
        try:
            actual, metadata = read_open_descriptor(index_fd, "locked audit index")
            assert_descriptor_path_nofollow(output, index_fd, "locked audit index")
            if actual != encoded or (metadata.st_mode & 0o777) != 0o400:
                raise AuditFinalizeError("published audit index bytes or mode differ")
        finally:
            os.close(index_fd)
        return payload
    except (KeyError, OSError, StrictArtifactError) as error:
        raise AuditFinalizeError(str(error)) from error
    finally:
        for binding in bindings.values():
            os.close(binding.descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--provenance", required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--prepare-job", type=int, required=True)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--audit-job", type=int, required=True)
    parser.add_argument("--preparation-binding", required=True)
    args = parser.parse_args()
    try:
        payload = finalize(
            args.out,
            json.loads(args.provenance),
            args.run_root,
            args.prepare_job,
            args.shards,
            args.audit_job,
            json.loads(args.preparation_binding),
        )
    except (AuditFinalizeError, json.JSONDecodeError, OSError, ValueError) as error:
        print(f"locked audit finalization rejected: {error}", file=sys.stderr)
        return 2
    print(canonical_json_bytes(payload).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
