from __future__ import annotations

import importlib.util
import io
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "wmi" / "install_pinned_competitors.py"
SPEC = importlib.util.spec_from_file_location("install_pinned_competitors", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


class ReleaseContractTests(unittest.TestCase):
    def test_release_urls_versions_and_archive_hashes_are_exact(self) -> None:
        self.assertEqual(INSTALLER.BUNDLE_NAME, "competitors-yices-2.7.0-cvc5-1.3.4")
        self.assertEqual(
            INSTALLER.PACKAGES["yices2"]["archive_sha256"],
            "49566b6f817692820538df78fe406878400d79810631c9372b2495bc81d3e00a",
        )
        self.assertEqual(
            INSTALLER.PACKAGES["cvc5"]["archive_sha256"],
            "dcdbfada0ce493ee98259c0816e0daafc561c223aadb3af298c2968e73ea39c6",
        )
        for package in INSTALLER.PACKAGES.values():
            self.assertTrue(package["url"].startswith("https://github.com/"))
            self.assertIn(package["version"], package["url"])

    def test_cli_is_default_off_before_argument_or_network_processing(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", "")},
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("default-off", completed.stderr)

    def test_tools_root_rejects_lexical_escape_before_creation(self) -> None:
        for path in (
            Path("relative"),
            Path("/tmp/work/tools"),
            Path("/work"),
            Path("/work/../tmp/escaped-tools"),
        ):
            with self.subTest(path=path):
                with self.assertRaises(INSTALLER.InstallError):
                    INSTALLER.prepare_tools_root(path)


class ArchivePathTests(unittest.TestCase):
    def test_member_paths_and_symlink_targets_fail_closed(self) -> None:
        self.assertEqual(
            INSTALLER.safe_member_path("package/bin/solver").as_posix(),
            "package/bin/solver",
        )
        invalid_members = (
            "",
            "/absolute",
            "../escape",
            "a/../escape",
            "a//b",
            "./a",
            "a\\b",
            "a\0b",
        )
        for member in invalid_members:
            with self.subTest(member=member):
                with self.assertRaises(INSTALLER.InstallError):
                    INSTALLER.safe_member_path(member)
        for target in ("", "/absolute", "../escape", "a/../escape", "a\\b"):
            with self.subTest(target=target):
                with self.assertRaises(INSTALLER.InstallError):
                    INSTALLER.safe_symlink_target("link", target)

    def test_exact_copy_rejects_short_and_overlong_streams(self) -> None:
        with tempfile.TemporaryDirectory(prefix="competitor exact copy ") as temp:
            root = Path(temp)
            INSTALLER.copy_exact(io.BytesIO(b"abc"), root / "exact", 3)
            self.assertEqual((root / "exact").read_bytes(), b"abc")
            with self.assertRaisesRegex(INSTALLER.InstallError, "size mismatch"):
                INSTALLER.copy_exact(io.BytesIO(b"ab"), root / "short", 3)
            with self.assertRaisesRegex(INSTALLER.InstallError, "exceeds declared"):
                INSTALLER.copy_exact(io.BytesIO(b"abcd"), root / "long", 3)


class SafeExtractionTests(unittest.TestCase):
    def test_tar_extracts_regular_executable_and_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="competitor tar ") as temp:
            root = Path(temp)
            archive = root / "good.tar.gz"
            payload = b"#!/bin/sh\nexit 0\n"
            with tarfile.open(archive, "w:gz") as bundle:
                directory = tarfile.TarInfo("package/bin")
                directory.type = tarfile.DIRTYPE
                bundle.addfile(directory)
                member = tarfile.TarInfo("package/bin/solver")
                member.mode = 0o755
                member.size = len(payload)
                bundle.addfile(member, io.BytesIO(payload))
            destination = root / "good"
            destination.mkdir()
            INSTALLER.extract_tar(archive, destination)
            solver = destination / "package" / "bin" / "solver"
            self.assertEqual(solver.read_bytes(), payload)
            self.assertTrue(stat.S_IMODE(solver.stat().st_mode) & stat.S_IXUSR)

            malicious = root / "bad.tar.gz"
            with tarfile.open(malicious, "w:gz") as bundle:
                member = tarfile.TarInfo("../escape")
                member.size = 1
                bundle.addfile(member, io.BytesIO(b"x"))
            bad_destination = root / "bad"
            bad_destination.mkdir()
            with self.assertRaisesRegex(INSTALLER.InstallError, "unsafe"):
                INSTALLER.extract_tar(malicious, bad_destination)
            self.assertFalse((root / "escape").exists())

    def test_zip_extracts_regular_executable_and_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="competitor zip ") as temp:
            root = Path(temp)
            archive = root / "good.zip"
            payload = b"#!/bin/sh\nexit 0\n"
            with zipfile.ZipFile(archive, "w") as bundle:
                info = zipfile.ZipInfo("package/bin/solver")
                info.external_attr = (stat.S_IFREG | 0o755) << 16
                bundle.writestr(info, payload)
            destination = root / "good"
            destination.mkdir()
            INSTALLER.extract_zip(archive, destination)
            solver = destination / "package" / "bin" / "solver"
            self.assertEqual(solver.read_bytes(), payload)
            self.assertTrue(stat.S_IMODE(solver.stat().st_mode) & stat.S_IXUSR)

            malicious = root / "bad.zip"
            with zipfile.ZipFile(malicious, "w") as bundle:
                bundle.writestr("../escape", b"x")
            bad_destination = root / "bad"
            bad_destination.mkdir()
            with self.assertRaisesRegex(INSTALLER.InstallError, "unsafe"):
                INSTALLER.extract_zip(malicious, bad_destination)
            self.assertFalse((root / "escape").exists())

    def test_tree_manifest_records_symlinked_directories_as_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="competitor tree ") as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            (real / "file").write_bytes(b"data")
            (root / "linkdir").symlink_to("real")
            records = INSTALLER.tree_manifest(root)
            by_path = {record["path"]: record for record in records}
            self.assertEqual(by_path["linkdir"], {
                "path": "linkdir",
                "target": "real",
                "type": "symlink",
            })
            self.assertEqual(by_path["real/file"]["sha256"], INSTALLER.sha256_file(real / "file"))


if __name__ == "__main__":
    unittest.main()
