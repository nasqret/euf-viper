from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "wmi" / "attest_sealed_build.py"
SPEC = importlib.util.spec_from_file_location("attest_sealed_build_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
ATTEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ATTEST)


def tar_bytes(members: list[tuple[str, bytes, int]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as archive:
        for name, content, mode in members:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = mode
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


class SealedBuildAttestationTests(unittest.TestCase):
    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(ATTEST.AttestationError, "duplicate JSON key"):
            ATTEST.parse_canonical(b'{"schema":1,"schema":2}\n', "fixture")

    def test_canonical_trace_binds_time_randomness_and_denies_network(self) -> None:
        raw = (
            b'41 clock_gettime(CLOCK_REALTIME, {tv_sec=7, tv_nsec=9}) = 0\n'
            b'41 getrandom("\\x01\\x02", 2, 0) = 2\n'
            b'42 openat(AT_FDCWD, "/work/input", O_RDONLY) = 3\n'
        )
        value = ATTEST.canonical_trace(raw, "/work", "production")
        self.assertEqual(value["channels"]["time_events"], 1)
        self.assertEqual(value["channels"]["randomness_events"], 1)
        self.assertIn("$WORKSPACE/input", value["canonical_lines"][2])
        self.assertTrue(value["canonical_lines"][0].startswith("$PID0 "))
        self.assertTrue(value["canonical_lines"][2].startswith("$PID1 "))
        for syscall in (
            b"41 connect(3, {sa_family=AF_UNIX}, 16) = 0\n",
            b"41 socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3\n",
        ):
            with self.assertRaisesRegex(ATTEST.AttestationError, "network syscall"):
                ATTEST.canonical_trace(syscall, "/work", "production")

    def test_source_bundle_reconstructs_exact_bytes_and_rejects_unsafe_members(self) -> None:
        content = b"bound source\n"
        manifest = {
            "files": [
                {
                    "bytes": len(content),
                    "category": "git",
                    "mode": "0444",
                    "path": "src/lib.rs",
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            ],
            "revision": "1" * 40,
            "schema": ATTEST.SOURCE_SCHEMA,
            "tree": "2" * 40,
        }
        manifest_raw = ATTEST.canonical_bytes(manifest)
        archive = tar_bytes(
            [
                ("src/lib.rs", content, 0o444),
                (".euf-viper-sealed-source-manifest.json", manifest_raw, 0o444),
            ]
        )
        reconstructed = ATTEST.verify_source_bundle(archive, manifest)
        self.assertEqual(reconstructed["file_count"], 1)
        unsafe = tar_bytes(
            [
                ("../src/lib.rs", content, 0o444),
                (".euf-viper-sealed-source-manifest.json", manifest_raw, 0o444),
            ]
        )
        with self.assertRaisesRegex(ATTEST.AttestationError, "non-file or duplicate"):
            ATTEST.verify_source_bundle(unsafe, manifest)

    def test_retained_input_archive_rejects_duplicate_objects(self) -> None:
        cargo = b"cargo bytes"
        rustc = b"rustc bytes"
        cargo_hash = hashlib.sha256(cargo).hexdigest()
        rustc_hash = hashlib.sha256(rustc).hexdigest()
        index = {
            "files": [
                {
                    "bytes": len(cargo),
                    "category": "rust_toolchain_input",
                    "mode": "0555",
                    "object": f"objects/{cargo_hash}",
                    "path": "/toolchain/bin/cargo",
                    "sha256": cargo_hash,
                },
                {
                    "bytes": len(rustc),
                    "category": "rust_toolchain_input",
                    "mode": "0555",
                    "object": f"objects/{rustc_hash}",
                    "path": "/toolchain/bin/rustc",
                    "sha256": rustc_hash,
                },
            ],
            "object_count": 2,
            "schema": ATTEST.INPUTS_SCHEMA,
        }
        index_raw = ATTEST.canonical_bytes(index)
        members = [
            (f"objects/{cargo_hash}", cargo, 0o555),
            (f"objects/{rustc_hash}", rustc, 0o555),
            ("retained-build-inputs.json", index_raw, 0o400),
        ]
        result = ATTEST.verify_input_bundle(tar_bytes(members), index_raw, index)
        self.assertEqual(result["cargo_sha256"], cargo_hash)
        with self.assertRaisesRegex(ATTEST.AttestationError, "unexpected member"):
            ATTEST.verify_input_bundle(
                tar_bytes([members[0], members[0], *members[1:]]),
                index_raw,
                index,
            )

    def test_retained_index_cannot_supply_unbound_fields(self) -> None:
        index = {
            "files": [],
            "object_count": 0,
            "schema": ATTEST.INPUTS_SCHEMA,
            "trusted": True,
        }
        raw = ATTEST.canonical_bytes(index)
        with self.assertRaisesRegex(ATTEST.AttestationError, "keys differ"):
            ATTEST.verify_input_bundle(tar_bytes([]), raw, index)


if __name__ == "__main__":
    unittest.main()
