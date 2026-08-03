from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UTILITY = ROOT / "scripts" / "bench" / "t11_build_closure.py"
def load_utility():
    spec = importlib.util.spec_from_file_location("t11_build_closure", UTILITY)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class T11BuildClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.utility = load_utility()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self._write(
            self.repository / "Cargo.toml",
            b'[package]\nname = "closure-probe"\nversion = "0.1.0"\n',
        )
        self._write(self.repository / "Cargo.lock", b"# exact lock\n")
        self._write(self.repository / "src" / "main.rs", b"fn main() {}\n")
        self._git("init", "-q")
        self._git("config", "user.name", "T11 Test")
        self._git("config", "user.email", "t11@example.invalid")
        self._git("add", ".")
        self._git("commit", "-qm", "fixture")
        self.source_commit = self._git("rev-parse", "HEAD^{commit}")
        self.source_tree = self._git("rev-parse", "HEAD^{tree}")
        self.inputs = self._make_inputs(self.root / "inputs-a", mtime=1_700_000_001)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write(path: Path, data: bytes, mode: int = 0o644, mtime: int = 1) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        os.utime(path, (mtime, mtime))

    def _make_inputs(self, base: Path, *, mtime: int) -> dict[str, str]:
        candidate = base / "candidate-binary"
        self._write(candidate, b"#!/bin/sh\nexit 0\n", 0o755, mtime)
        candidate_sha256 = self._sha256(candidate)
        inventory = {
            "candidate_sha256": candidate_sha256,
            "platform": "linux-x86_64",
            "runtime_files": [],
            "schema": self.utility.DEPENDENCY_INVENTORY_SCHEMA,
        }
        inventory_path = base / "dependency-inventory"
        self._write(inventory_path, self.utility._canonical_json(inventory), mtime=mtime + 1)
        receipt = {
            "binary_dependencies_sha256": self._sha256(inventory_path),
            "build_command": [
                "cargo", "build", "--locked", "--features", "certificates",
                "--release", "--target", "x86_64-unknown-linux-gnu",
            ],
            "candidate_bytes": candidate.stat().st_size,
            "candidate_sha256": candidate_sha256,
            "cargo_lock_sha256": self._sha256(self.repository / "Cargo.lock"),
            "cargo_toml_sha256": self._sha256(self.repository / "Cargo.toml"),
            "features": ["certificates"],
            "profile": "release",
            "rust_target": "x86_64-unknown-linux-gnu",
            "schema": self.utility.BUILD_RECEIPT_SCHEMA,
            "source_commit": self.source_commit,
            "source_tree": self.source_tree,
        }
        receipt_path = base / "build-receipt"
        self._write(receipt_path, self.utility._canonical_json(receipt), mtime=mtime + 2)
        return {
            "build-receipt": str(receipt_path),
            "candidate-binary": str(candidate),
            "dependency-inventory": str(inventory_path),
        }

    def _git(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repository), *arguments],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _create(self, name: str = "closure.tar") -> tuple[Path, object]:
        archive = self.root / name
        report = self.utility.create_archive(
            str(archive), self.inputs, str(self.repository)
        )
        return archive, report

    def _members(self, archive: Path) -> list[dict[str, object]]:
        raw = archive.read_bytes()
        members: list[dict[str, object]] = []
        offset = 0
        while True:
            header = raw[offset : offset + self.utility.BLOCK_SIZE]
            self.assertEqual(len(header), self.utility.BLOCK_SIZE)
            offset += self.utility.BLOCK_SIZE
            if header == b"\0" * self.utility.BLOCK_SIZE:
                self.assertEqual(
                    raw[offset : offset + self.utility.BLOCK_SIZE],
                    b"\0" * self.utility.BLOCK_SIZE,
                )
                offset += self.utility.BLOCK_SIZE
                self.assertEqual(offset, len(raw))
                break
            name, kind, mode, size = self.utility._parse_header(header)
            data = raw[offset : offset + size]
            self.assertEqual(len(data), size)
            offset += size
            padding_size = (-size) % self.utility.BLOCK_SIZE
            padding = raw[offset : offset + padding_size]
            self.assertEqual(padding, b"\0" * padding_size)
            offset += padding_size
            members.append(
                {
                    "name": name,
                    "kind": kind,
                    "mode": mode,
                    "data": data,
                    "header": header,
                }
            )
        return members

    def _write_members(
        self,
        name: str,
        members: list[dict[str, object]],
        *,
        trailing: bytes = b"",
    ) -> Path:
        archive = self.root / name
        with archive.open("wb") as stream:
            for member in members:
                data = member["data"]
                assert isinstance(data, bytes)
                header = member.get("header")
                if header is None:
                    header = self.utility._ustar_header(
                        member["name"], member["kind"], member["mode"], len(data)
                    )
                assert isinstance(header, bytes)
                stream.write(header)
                stream.write(data)
                stream.write(b"\0" * ((-len(data)) % self.utility.BLOCK_SIZE))
            stream.write(b"\0" * (2 * self.utility.BLOCK_SIZE))
            stream.write(trailing)
        archive.chmod(0o444)
        return archive

    @staticmethod
    def _rechecksum(header: bytearray) -> bytes:
        header[148:156] = b"        "
        header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
        return bytes(header)

    def _renamed_header(self, header: bytes, name: bytes) -> bytes:
        self.assertLessEqual(len(name), 100)
        changed = bytearray(header)
        changed[0:100] = b"\0" * 100
        changed[345:500] = b"\0" * 155
        changed[0 : len(name)] = name
        return self._rechecksum(changed)

    def _type_header(self, header: bytes, typeflag: bytes) -> bytes:
        self.assertEqual(len(typeflag), 1)
        changed = bytearray(header)
        changed[156:157] = typeflag
        return self._rechecksum(changed)

    def test_required_label_and_tool_contract_is_explicit(self) -> None:
        self.assertEqual(
            dict(self.utility.REQUIRED_ROOT_KINDS),
            {
                "build-receipt": "file",
                "candidate-binary": "file",
                "dependency-inventory": "file",
            },
        )

    def test_create_is_reproducible_and_manifest_is_canonical(self) -> None:
        archive_a, report_a = self._create("a.tar")
        inputs_b = self._make_inputs(self.root / "inputs-b", mtime=1_800_000_001)
        archive_b = self.root / "b.tar"
        report_b = self.utility.create_archive(
            str(archive_b), inputs_b, str(self.repository)
        )

        self.assertEqual(archive_a.read_bytes(), archive_b.read_bytes())
        self.assertEqual(report_a, report_b)
        self.assertEqual(report_a.archive_sha256, self._sha256(archive_a))
        self.assertEqual(stat.S_IMODE(archive_a.stat().st_mode), 0o444)

        members = self._members(archive_a)
        self.assertEqual(members[0]["name"], self.utility.MANIFEST_NAME)
        manifest_bytes = members[0]["data"]
        assert isinstance(manifest_bytes, bytes)
        manifest = json.loads(manifest_bytes)
        self.assertEqual(manifest_bytes, self.utility._canonical_json(manifest))
        self.assertEqual(manifest["source"]["commit"], self.source_commit)
        self.assertEqual(manifest["source"]["tree"], self.source_tree)
        roots = {root["label"]: root for root in manifest["roots"]}
        self.assertEqual(roots["candidate-binary"]["kind"], "file")
        self.assertEqual(roots["build-receipt"]["kind"], "file")
        self.assertEqual(roots["dependency-inventory"]["kind"], "file")
        self.assertEqual(
            manifest["prebuilt"],
            {
                "build_receipt": "payload/build-receipt",
                "build_receipt_sha256": report_a.build_receipt_sha256,
                "candidate": "payload/candidate-binary",
                "candidate_sha256": report_a.candidate_sha256,
                "dependency_inventory": "payload/dependency-inventory",
                "dependency_inventory_sha256": report_a.dependency_inventory_sha256,
            },
        )
        self.assertEqual(
            [root["label"] for root in manifest["roots"]],
            sorted(self.utility.REQUIRED_ROOT_KINDS),
        )
        self.assertEqual(
            [entry["path"] for entry in manifest["entries"]],
            sorted(entry["path"] for entry in manifest["entries"]),
        )

        verified = self.utility.verify_archive(
            str(archive_a), report_a.archive_sha256
        )
        self.assertEqual(verified, report_a)

    def test_extract_creates_complete_read_only_inventory(self) -> None:
        archive, report = self._create()
        destination = self.root / "extracted"
        extracted = self.utility.extract_archive(
            str(archive), report.archive_sha256, str(destination)
        )
        self.assertEqual(extracted, report)
        self.assertEqual(
            (destination / "payload" / "candidate-binary").read_bytes(),
            b"#!/bin/sh\nexit 0\n",
        )
        self.assertEqual(
            stat.S_IMODE(
                (destination / "payload" / "candidate-binary").stat().st_mode
            ),
            0o555,
        )
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o555)
        for path in [destination, *destination.rglob("*")]:
            self.assertEqual(
                stat.S_IMODE(path.stat().st_mode) & 0o222,
                0,
                f"extracted path remains writable: {path}",
            )

        with self.assertRaisesRegex(self.utility.ClosureError, "already exists"):
            self.utility.extract_archive(
                str(archive), report.archive_sha256, str(destination)
            )

    @unittest.skipUnless(
        sys.platform.startswith("linux") and Path("/proc/self/fd").is_dir(),
        "descriptor-bound closure input requires Linux proc-fd support",
    )
    def test_inherited_proc_descriptor_is_verified_without_path_reopen(self) -> None:
        archive, report = self._create()
        descriptor = os.open(archive, os.O_RDONLY | os.O_CLOEXEC)
        try:
            proc_path = f"/proc/self/fd/{descriptor}"
            with self.assertRaisesRegex(
                self.utility.ClosureError, "explicitly inherited"
            ):
                self.utility.verify_archive(proc_path, report.archive_sha256)
            os.set_inheritable(descriptor, True)
            self.assertEqual(
                self.utility.verify_archive(proc_path, report.archive_sha256),
                report,
            )
            destination = self.root / "descriptor-extracted"
            self.assertEqual(
                self.utility.extract_archive(
                    proc_path, report.archive_sha256, str(destination)
                ),
                report,
            )
        finally:
            os.close(descriptor)

    def test_command_line_create_verify_and_extract(self) -> None:
        archive = self.root / "cli.tar"
        create_command = [
            sys.executable,
            str(UTILITY),
            "create",
            "--output",
            str(archive),
            "--source-repository",
            str(self.repository),
        ]
        for label in reversed(sorted(self.inputs)):
            create_command.extend(["--input", f"{label}={self.inputs[label]}"])
        created = subprocess.run(
            create_command, check=True, capture_output=True, text=True
        )
        receipt = json.loads(created.stdout)
        self.assertEqual(receipt["status"], "verified")
        self.assertEqual(receipt["archive_sha256"], self._sha256(archive))

        verified = subprocess.run(
            [
                sys.executable,
                str(UTILITY),
                "verify",
                "--archive",
                str(archive),
                "--sha256",
                receipt["archive_sha256"],
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(json.loads(verified.stdout)["archive_sha256"], receipt["archive_sha256"])

        destination = self.root / "cli-extract"
        extracted = subprocess.run(
            [
                sys.executable,
                str(UTILITY),
                "extract",
                "--archive",
                str(archive),
                "--sha256",
                receipt["archive_sha256"],
                "--destination",
                str(destination),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(json.loads(extracted.stdout)["destination"], str(destination))

    def test_create_rejects_bad_contract_and_refuses_replacement(self) -> None:
        missing = dict(self.inputs)
        del missing["candidate-binary"]
        with self.assertRaisesRegex(self.utility.ClosureError, "labels differ"):
            self.utility.create_archive(
                str(self.root / "missing.tar"), missing, str(self.repository)
            )

        extra = dict(self.inputs)
        extra["unexpected"] = self.inputs["candidate-binary"]
        with self.assertRaisesRegex(self.utility.ClosureError, "labels differ"):
            self.utility.create_archive(
                str(self.root / "extra.tar"), extra, str(self.repository)
            )

        self._write(self.repository / "untracked", b"dirty\n")
        with self.assertRaisesRegex(self.utility.ClosureError, "completely clean"):
            self.utility.create_archive(
                str(self.root / "dirty.tar"), self.inputs, str(self.repository)
            )
        (self.repository / "untracked").unlink()

        output = self.root / "exists.tar"
        output.write_bytes(b"preserve-me")
        with self.assertRaisesRegex(self.utility.ClosureError, "already exists"):
            self.utility.create_archive(str(output), self.inputs, str(self.repository))
        self.assertEqual(output.read_bytes(), b"preserve-me")

    def test_create_rejects_mismatched_prebuilt_provenance(self) -> None:
        receipt_path = Path(self.inputs["build-receipt"])
        receipt = json.loads(receipt_path.read_bytes())
        receipt["source_tree"] = "0" * 40
        self._write(receipt_path, self.utility._canonical_json(receipt))
        with self.assertRaisesRegex(
            self.utility.ClosureError,
            "build receipt source_tree differs from the prebuilt contract",
        ):
            self.utility.create_archive(
                str(self.root / "bad-source-tree.tar"),
                self.inputs,
                str(self.repository),
            )

        inputs = self._make_inputs(self.root / "inputs-b", mtime=1_700_000_101)
        inventory_path = Path(inputs["dependency-inventory"])
        inventory = json.loads(inventory_path.read_bytes())
        inventory["candidate_sha256"] = "0" * 64
        self._write(inventory_path, self.utility._canonical_json(inventory))
        with self.assertRaisesRegex(
            self.utility.ClosureError,
            "dependency inventory candidate SHA-256 differs",
        ):
            self.utility.create_archive(
                str(self.root / "bad-inventory.tar"),
                inputs,
                str(self.repository),
            )

    def test_create_rejects_symlinks_hardlinks_and_special_files(self) -> None:
        candidate = Path(self.inputs["candidate-binary"])
        candidate_link = self.root / "candidate-link"
        candidate_link.symlink_to(candidate)
        linked_inputs = dict(self.inputs)
        linked_inputs["candidate-binary"] = str(candidate_link)
        with self.assertRaises(self.utility.ClosureError):
            self.utility.create_archive(
                str(self.root / "symlink.tar"), linked_inputs, str(self.repository)
            )

        hardlink = self.root / "candidate-hardlink"
        os.link(candidate, hardlink)
        linked_inputs["candidate-binary"] = str(hardlink)
        with self.assertRaisesRegex(self.utility.ClosureError, "physical link|hard link"):
            duplicate_inputs = dict(linked_inputs)
            duplicate_inputs["build-receipt"] = str(candidate)
            self.utility.create_archive(
                str(self.root / "hardlink.tar"), duplicate_inputs, str(self.repository)
            )
        hardlink.unlink()

        if hasattr(os, "mkfifo"):
            fifo = self.root / "candidate.pipe"
            os.mkfifo(fifo)
            fifo_inputs = dict(self.inputs)
            fifo_inputs["candidate-binary"] = str(fifo)
            try:
                with self.assertRaisesRegex(self.utility.ClosureError, "regular file"):
                    self.utility.create_archive(
                        str(self.root / "fifo.tar"), fifo_inputs, str(self.repository)
                    )
            finally:
                fifo.unlink()

    def test_verify_requires_exact_hash_read_only_regular_archive(self) -> None:
        archive, report = self._create()
        with self.assertRaisesRegex(self.utility.ClosureError, "SHA-256 mismatch"):
            self.utility.verify_archive(str(archive), "0" * 64)
        with self.assertRaisesRegex(self.utility.ClosureError, "64 lowercase"):
            self.utility.verify_archive(str(archive), report.archive_sha256.upper())

        archive.chmod(0o644)
        with self.assertRaisesRegex(self.utility.ClosureError, "write permission"):
            self.utility.verify_archive(str(archive), report.archive_sha256)
        archive.chmod(0o444)

        linked = self.root / "archive-link.tar"
        linked.symlink_to(archive)
        with self.assertRaises(self.utility.ClosureError):
            self.utility.verify_archive(str(linked), report.archive_sha256)

        hardlinked = self.root / "archive-hardlink.tar"
        os.link(archive, hardlinked)
        try:
            with self.assertRaisesRegex(self.utility.ClosureError, "physical link"):
                self.utility.verify_archive(str(archive), report.archive_sha256)
        finally:
            hardlinked.unlink()

    def test_rejects_traversal_absolute_and_duplicate_archive_names(self) -> None:
        archive, _ = self._create()
        original = self._members(archive)
        payload_index = next(
            index for index, member in enumerate(original) if member["name"] != "manifest.json"
        )
        for case, malicious_name in (
            ("traversal", b"../escape"),
            ("absolute", b"/escape"),
            ("backslash-traversal", b"..\\escape"),
        ):
            with self.subTest(case=case):
                members = [dict(member) for member in original]
                members[payload_index]["header"] = self._renamed_header(
                    members[payload_index]["header"], malicious_name
                )
                malformed = self._write_members(f"{case}.tar", members)
                with self.assertRaisesRegex(
                    self.utility.ClosureError, "canonical|forbidden|invalid path"
                ):
                    self.utility.verify_archive(str(malformed), self._sha256(malformed))

        members = [dict(member) for member in original]
        members.append(dict(members[-1]))
        duplicate = self._write_members("duplicate.tar", members)
        with self.assertRaisesRegex(self.utility.ClosureError, "duplicate archive member"):
            self.utility.verify_archive(str(duplicate), self._sha256(duplicate))

    def test_rejects_link_device_socket_and_fifo_tar_types(self) -> None:
        archive, _ = self._create()
        original = self._members(archive)
        file_index = next(
            index for index, member in enumerate(original) if member["kind"] == "file" and index
        )
        for label, typeflag in {
            "hardlink": b"1",
            "symlink": b"2",
            "character-device": b"3",
            "block-device": b"4",
            "fifo": b"6",
            "socket-extension": b"s",
        }.items():
            with self.subTest(member_type=label):
                members = [dict(member) for member in original]
                members[file_index]["header"] = self._type_header(
                    members[file_index]["header"], typeflag
                )
                malformed = self._write_members(f"type-{label}.tar", members)
                with self.assertRaisesRegex(self.utility.ClosureError, "forbidden member type"):
                    self.utility.verify_archive(str(malformed), self._sha256(malformed))

    def test_rejects_noncanonical_or_inconsistent_manifest(self) -> None:
        archive, _ = self._create()
        original = self._members(archive)
        manifest = json.loads(original[0]["data"])

        pretty = [dict(member) for member in original]
        pretty[0]["data"] = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
        pretty[0].pop("header")
        malformed = self._write_members("pretty-manifest.tar", pretty)
        with self.assertRaisesRegex(self.utility.ClosureError, "not canonical"):
            self.utility.verify_archive(str(malformed), self._sha256(malformed))

        duplicate_key = [dict(member) for member in original]
        duplicate_key[0]["data"] = b'{"schema":"x","schema":"y"}\n'
        duplicate_key[0].pop("header")
        malformed = self._write_members("duplicate-key.tar", duplicate_key)
        with self.assertRaisesRegex(self.utility.ClosureError, "duplicate JSON"):
            self.utility.verify_archive(str(malformed), self._sha256(malformed))

        duplicated_entry = json.loads(json.dumps(manifest))
        duplicated_entry["entries"].append(dict(duplicated_entry["entries"][-1]))
        duplicate_manifest = [dict(member) for member in original]
        duplicate_manifest[0]["data"] = self.utility._canonical_json(duplicated_entry)
        duplicate_manifest[0].pop("header")
        malformed = self._write_members("duplicate-manifest-entry.tar", duplicate_manifest)
        with self.assertRaisesRegex(self.utility.ClosureError, "duplicate manifest entry"):
            self.utility.verify_archive(str(malformed), self._sha256(malformed))

        missing = [dict(member) for member in original[:-1]]
        malformed = self._write_members("missing.tar", missing)
        with self.assertRaisesRegex(self.utility.ClosureError, "missing manifest entries"):
            self.utility.verify_archive(str(malformed), self._sha256(malformed))

        extra = [dict(member) for member in original]
        extra.append(
            {
                "name": "payload/unexpected",
                "kind": "file",
                "mode": 0o444,
                "data": b"unexpected\n",
            }
        )
        malformed = self._write_members("extra-member.tar", extra)
        with self.assertRaisesRegex(self.utility.ClosureError, "extra member"):
            self.utility.verify_archive(str(malformed), self._sha256(malformed))

    def test_rejects_payload_mode_size_hash_and_header_metadata_drift(self) -> None:
        archive, _ = self._create()
        original = self._members(archive)
        file_index = next(
            index
            for index, member in enumerate(original)
            if member["name"] == "payload/candidate-binary"
        )

        mode = [dict(member) for member in original]
        mode[file_index].pop("header")
        mode[file_index]["mode"] = 0o444
        malformed = self._write_members("mode.tar", mode)
        with self.assertRaisesRegex(self.utility.ClosureError, "mode mismatch"):
            self.utility.verify_archive(str(malformed), self._sha256(malformed))

        size = [dict(member) for member in original]
        size[file_index].pop("header")
        size[file_index]["data"] = size[file_index]["data"] + b"x"
        malformed = self._write_members("size.tar", size)
        with self.assertRaisesRegex(self.utility.ClosureError, "size mismatch"):
            self.utility.verify_archive(str(malformed), self._sha256(malformed))

        content = [dict(member) for member in original]
        content[file_index].pop("header")
        data = bytearray(content[file_index]["data"])
        data[0] ^= 1
        content[file_index]["data"] = bytes(data)
        malformed = self._write_members("content.tar", content)
        with self.assertRaisesRegex(self.utility.ClosureError, "digest mismatch"):
            self.utility.verify_archive(str(malformed), self._sha256(malformed))

        metadata = [dict(member) for member in original]
        changed_header = bytearray(metadata[file_index]["header"])
        changed_header[108:116] = b"0000001\0"
        metadata[file_index]["header"] = self._rechecksum(changed_header)
        malformed = self._write_members("metadata.tar", metadata)
        with self.assertRaisesRegex(self.utility.ClosureError, "not normalized"):
            self.utility.verify_archive(str(malformed), self._sha256(malformed))

    def test_rejects_nonzero_padding_and_trailing_bytes(self) -> None:
        archive, _ = self._create()
        raw = bytearray(archive.read_bytes())
        members = self._members(archive)
        first_size = len(members[0]["data"])
        padding = (-first_size) % self.utility.BLOCK_SIZE
        self.assertGreater(padding, 0)
        padding_offset = self.utility.BLOCK_SIZE + first_size
        raw[padding_offset] = 1
        malformed = self.root / "padding.tar"
        malformed.write_bytes(raw)
        malformed.chmod(0o444)
        with self.assertRaisesRegex(self.utility.ClosureError, "padding is nonzero"):
            self.utility.verify_archive(str(malformed), self._sha256(malformed))

        trailing = self._write_members(
            "trailing.tar", [dict(member) for member in members], trailing=b"x"
        )
        with self.assertRaisesRegex(self.utility.ClosureError, "trailing data"):
            self.utility.verify_archive(str(trailing), self._sha256(trailing))


if __name__ == "__main__":
    unittest.main()
