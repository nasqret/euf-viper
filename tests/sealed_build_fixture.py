from __future__ import annotations

from typing import Any


def independent_attestation(
    *,
    artifacts: dict[str, Any],
    features: list[str],
    toolchain: dict[str, str],
    revision: str,
    tree: str,
    source_manifest_sha256: str,
    closure_sha256: str,
    build_manifest_sha256: str,
    attestor_sha256: str = "8" * 64,
) -> dict[str, Any]:
    return {
        "artifacts": artifacts,
        "attestor_sha256": attestor_sha256,
        "build_inputs": {
            "archive_sha256": "9" * 64,
            "cargo_sha256": "a" * 64,
            "file_count": 2,
            "index_sha256": "b" * 64,
            "object_count": 2,
            "rustc_sha256": "c" * 64,
        },
        "build_manifest_sha256": build_manifest_sha256,
        "closure_sha256": closure_sha256,
        "features": features,
        "schema": "euf-viper.sealed-build-attestation.v1",
        "source": {
            "bundle_sha256": "d" * 64,
            "file_count": 1,
            "manifest_sha256": source_manifest_sha256,
            "revision": revision,
            "tree": tree,
        },
        "status": "accepted",
        "toolchain": toolchain,
        "traces": {
            "canonical_sha256": "e" * 64,
            "discovery_raw_sha256": "f" * 64,
            "network": "denied-and-namespaced",
            "production_raw_sha256": "0" * 64,
            "randomness_events": 1,
            "time_events": 1,
        },
    }
