from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "build_rollback_control_manifest.py"
SPEC = importlib.util.spec_from_file_location("build_rollback_control_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def write_row(root: Path, identifier: int, relative_path: str, status: str, size: int) -> dict:
    source = root / "corpus" / relative_path
    source.parent.mkdir(parents=True, exist_ok=True)
    payload = ((relative_path + "\n").encode("utf-8") * (size // (len(relative_path) + 1) + 1))[
        :size
    ]
    source.write_bytes(payload)
    return {
        "bytes": len(payload),
        "id": identifier,
        "logic": "QF_UF",
        "path": str(source),
        "relative_path": relative_path,
        "sha256": digest(payload),
        "status": status,
    }


def write_manifest(path: Path, rows: list[dict]) -> None:
    path.write_bytes(b"".join(BUILDER.canonical_bytes(row) for row in rows))


def run_builder(manifest: Path, output: Path, summary: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            str(manifest),
            "--out",
            str(output),
            "--summary",
            str(summary),
            "--anti-targets-per-status",
            "2",
            "--max-anti-target-bytes",
            "128",
            "--seed",
            "hermetic-selection",
            *extra,
        ],
        text=True,
        capture_output=True,
        check=False,
    )


class RollbackControlManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="rollback manifest ")
        self.root = Path(self.temp_dir.name)
        self.rows: list[dict] = []
        identifier = 0
        for relative_path, status in BUILDER.TARGETS:
            self.rows.append(write_row(self.root, identifier, relative_path, status, 73))
            identifier += 1
        for status in ("sat", "unsat"):
            for index in range(5):
                relative_path = f"QF_UF/control-{status}/case-{index}.smt2"
                self.rows.append(
                    write_row(self.root, identifier, relative_path, status, 40 + index)
                )
                identifier += 1
        self.rows.append(
            write_row(
                self.root,
                identifier,
                "QF_UF/2018-Goel-hwbench/not-a-target.smt2",
                "sat",
                32,
            )
        )
        identifier += 1
        self.rows.append(
            write_row(
                self.root,
                identifier,
                "QF_UF/oversized/anti.smt2",
                "unsat",
                129,
            )
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_selection_is_deterministic_balanced_and_source_bound(self) -> None:
        first_manifest = self.root / "first-source.jsonl"
        second_manifest = self.root / "second-source.jsonl"
        write_manifest(first_manifest, list(reversed(self.rows)))
        write_manifest(second_manifest, self.rows[::2] + self.rows[1::2])
        first_out = self.root / "first.jsonl"
        second_out = self.root / "second.jsonl"

        first = run_builder(first_manifest, first_out, self.root / "first-summary.json")
        second = run_builder(second_manifest, second_out, self.root / "second-summary.json")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first_out.read_bytes(), second_out.read_bytes())

        selected = [json.loads(line) for line in first_out.read_text().splitlines()]
        self.assertEqual(len(selected), 16)
        self.assertEqual(
            [row["relative_path"] for row in selected[:12]],
            [path for path, _ in BUILDER.TARGETS],
        )
        self.assertTrue(all(row["control_class"] == "target" for row in selected[:12]))
        anti = selected[12:]
        self.assertEqual(Counter(row["status"] for row in anti), {"sat": 2, "unsat": 2})
        self.assertTrue(all(row["control_class"] == "anti-target" for row in anti))
        self.assertTrue(all(not row["relative_path"].startswith(BUILDER.GOEL_PREFIX) for row in anti))
        self.assertTrue(all(row["bytes"] <= 128 for row in anti))

        original = {row["relative_path"]: row for row in self.rows}
        for row in selected:
            self.assertEqual(row["path"], original[row["relative_path"]]["path"])
            self.assertEqual(row["sha256"], original[row["relative_path"]]["sha256"])

        summary = json.loads((self.root / "first-summary.json").read_text())
        expected_hash = summary.pop("summary_sha256")
        summary["summary_sha256"] = ""
        self.assertEqual(expected_hash, digest(BUILDER.canonical_bytes(summary)))
        self.assertEqual(summary["anti_target_status_counts"], {"sat": 2, "unsat": 2})
        self.assertEqual(summary["source_verification"], "verified")

    def test_missing_target_and_source_tampering_fail_closed(self) -> None:
        missing_manifest = self.root / "missing.jsonl"
        write_manifest(missing_manifest, self.rows[1:])
        missing = run_builder(
            missing_manifest,
            self.root / "missing-out.jsonl",
            self.root / "missing-summary.json",
        )
        self.assertEqual(missing.returncode, 2)
        self.assertIn("required rollback target is missing", missing.stderr)

        stale_manifest = self.root / "stale.jsonl"
        write_manifest(stale_manifest, self.rows)
        Path(self.rows[0]["path"]).write_text("tampered", encoding="utf-8")
        stale = run_builder(
            stale_manifest,
            self.root / "stale-out.jsonl",
            self.root / "stale-summary.json",
        )
        self.assertEqual(stale.returncode, 2)
        self.assertIn("source byte count drift", stale.stderr)
        self.assertFalse((self.root / "stale-out.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
