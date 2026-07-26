from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PREPARE = ROOT / "scripts" / "helios" / "prepare_competitor_bundle.py"
VERIFY = ROOT / "scripts" / "helios" / "verify_competitor_bundle.py"


def elf_x86_64(marker: bytes) -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[18:20] = (62).to_bytes(2, "little")
    return bytes(header) + marker


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ComparatorBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        payloads = {
            "z3": elf_x86_64(b"z3"),
            "libz3": elf_x86_64(b"libz3"),
            "cvc5": elf_x86_64(b"cvc5"),
            "yices2": elf_x86_64(b"yices2"),
            "opensmt": elf_x86_64(b"opensmt"),
        }
        self.archives = {
            "z3": self.root / "z3.whl",
            "cvc5": self.root / "cvc5.zip",
            "yices2": self.root / "yices.tar.gz",
            "opensmt": self.root / "opensmt.tar.bz2",
        }
        with zipfile.ZipFile(self.archives["z3"], "w") as archive:
            archive.writestr("z3_solver-4.16.0.0.data/data/bin/z3", payloads["z3"])
            archive.writestr("z3/lib/libz3.so.4.16", payloads["libz3"])
        with zipfile.ZipFile(self.archives["cvc5"], "w") as archive:
            archive.writestr(
                "cvc5-Linux-x86_64-static/bin/cvc5", payloads["cvc5"]
            )
        self._write_tar(
            self.archives["yices2"],
            "w:gz",
            "yices-2.7.0/bin/yices-smt2",
            payloads["yices2"],
        )
        self._write_tar(
            self.archives["opensmt"], "w:bz2", "opensmt", payloads["opensmt"]
        )
        artifact_keys = {
            "z3": "linux-x86_64-manylinux-2.27-wheel",
            "cvc5": "linux-x86_64",
            "yices2": "linux-x86_64",
            "opensmt": "linux-x86_64",
        }
        versions = {"z3": "4.16.0", "cvc5": "1.3.4", "yices2": "2.7.0", "opensmt": "2.9.2"}
        release = {
            "schema_version": 1,
            "solvers": [
                {
                    "artifacts": {
                        artifact_keys[identifier]: {
                            "sha256": sha256(self.archives[identifier]),
                            "url": f"https://example.test/{self.archives[identifier].name}",
                        }
                    },
                    "id": identifier,
                    "tag": f"tag-{identifier}",
                    "version": versions[identifier],
                }
                for identifier in ("z3", "cvc5", "yices2", "opensmt")
            ],
        }
        self.release_lock = self.root / "release.json"
        self.release_lock.write_text(json.dumps(release), encoding="utf-8")
        self.bundle = self.root / "bundle"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write_tar(path: Path, mode: str, name: str, payload: bytes) -> None:
        with tarfile.open(path, mode) as archive:
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mode = 0o755
            archive.addfile(member, io.BytesIO(payload))

    def prepare(self) -> subprocess.CompletedProcess[str]:
        arguments = [
            sys.executable,
            str(PREPARE),
            "prepare",
            "--release-lock",
            str(self.release_lock),
        ]
        for identifier, path in self.archives.items():
            arguments.extend(("--artifact", f"{identifier}={path}"))
        arguments.extend(("--out", str(self.bundle)))
        return subprocess.run(arguments, check=False, capture_output=True, text=True)

    def verify(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(VERIFY),
                "--bundle-root",
                str(self.bundle),
                "--receipt",
                str(self.bundle / "receipt.json"),
                "--release-lock",
                str(self.release_lock),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_prepares_and_verifies_exact_minimal_bundle(self) -> None:
        prepared = self.prepare()
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        verified = self.verify()
        self.assertEqual(verified.returncode, 0, verified.stderr)
        receipt = json.loads((self.bundle / "receipt.json").read_text())
        self.assertEqual(len(receipt["archives"]), 4)
        self.assertEqual(len(receipt["files"]), 5)
        self.assertEqual(
            {record["path"] for record in receipt["files"]},
            {
                "bin/cvc5",
                "bin/opensmt",
                "bin/yices-smt2",
                "bin/z3",
                "lib/libz3.so.4.16",
            },
        )

    def test_verifier_rejects_unrecorded_payload(self) -> None:
        prepared = self.prepare()
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        self.bundle.chmod(0o755)
        extra = self.bundle / "extra"
        extra.write_bytes(elf_x86_64(b"extra"))
        verified = self.verify()
        self.assertEqual(verified.returncode, 2)
        self.assertIn("missing or unrecorded files", verified.stderr)


if __name__ == "__main__":
    unittest.main()
