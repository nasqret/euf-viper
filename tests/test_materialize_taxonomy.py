from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATERIALIZER = ROOT / "scripts" / "helios" / "materialize_taxonomy.py"


class TaxonomyCacheTests(unittest.TestCase):
    def run_materializer(
        self,
        *,
        manifest: Path,
        repository_root: Path,
        builder: Path,
        cache_root: Path,
        taxonomy_out: Path,
        split_out: Path,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(MATERIALIZER),
                str(manifest),
                "--repository-root",
                str(repository_root),
                "--builder",
                str(builder),
                "--cache-root",
                str(cache_root),
                "--taxonomy-out",
                str(taxonomy_out),
                "--split-out",
                str(split_out),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_cache_hit_is_byte_identical_and_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "case.smt2"
            source.write_text("(set-logic QF_UF)\n(check-sat)\n", encoding="ascii")
            manifest = root / "manifest.jsonl"
            manifest.write_text(
                json.dumps(
                    {
                        "path": str(source),
                        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                        "status": "sat",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="ascii",
            )
            counter = root / "builder-count.txt"
            builder = root / "builder.py"
            builder.write_text(
                textwrap.dedent(
                    f"""
                    import argparse
                    from pathlib import Path

                    parser = argparse.ArgumentParser()
                    parser.add_argument("manifest")
                    parser.add_argument("--repository-root")
                    parser.add_argument("--taxonomy-out", type=Path, required=True)
                    parser.add_argument("--split-out", type=Path, required=True)
                    args = parser.parse_args()
                    counter = Path({str(counter)!r})
                    count = int(counter.read_text()) + 1 if counter.exists() else 1
                    counter.write_text(str(count))
                    args.taxonomy_out.write_text('{{"family":"QG"}}\\n')
                    args.split_out.write_text('{{"seed":"fixed"}}\\n')
                    """
                ).lstrip(),
                encoding="ascii",
            )
            cache_root = root / "cache"
            first_taxonomy = root / "first-taxonomy.jsonl"
            first_split = root / "first-split.json"
            first = self.run_materializer(
                manifest=manifest,
                repository_root=root,
                builder=builder,
                cache_root=cache_root,
                taxonomy_out=first_taxonomy,
                split_out=first_split,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            first_report = json.loads(first.stdout)
            self.assertFalse(first_report["cache_hit"])

            second_taxonomy = root / "second-taxonomy.jsonl"
            second_split = root / "second-split.json"
            second = self.run_materializer(
                manifest=manifest,
                repository_root=root,
                builder=builder,
                cache_root=cache_root,
                taxonomy_out=second_taxonomy,
                split_out=second_split,
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            second_report = json.loads(second.stdout)
            self.assertTrue(second_report["cache_hit"])
            self.assertEqual(first_report["cache_key"], second_report["cache_key"])
            self.assertEqual(counter.read_text(encoding="ascii"), "1")
            self.assertEqual(first_taxonomy.read_bytes(), second_taxonomy.read_bytes())
            self.assertEqual(first_split.read_bytes(), second_split.read_bytes())

            cached_taxonomy = Path(second_report["cache_entry"]) / "taxonomy.jsonl"
            cached_taxonomy.chmod(0o644)
            cached_taxonomy.write_text('{"tampered":true}\n', encoding="ascii")
            third = self.run_materializer(
                manifest=manifest,
                repository_root=root,
                builder=builder,
                cache_root=cache_root,
                taxonomy_out=root / "third-taxonomy.jsonl",
                split_out=root / "third-split.json",
            )
            self.assertEqual(third.returncode, 2)
            self.assertIn("cached output hash drifted", third.stderr)
            self.assertEqual(counter.read_text(encoding="ascii"), "1")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_symlink_cache_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "case.smt2"
            source.write_text("(check-sat)\n", encoding="ascii")
            manifest = root / "manifest.jsonl"
            manifest.write_text(json.dumps({"path": str(source)}) + "\n")
            builder = root / "builder.py"
            builder.write_text("raise SystemExit(99)\n", encoding="ascii")
            actual_cache = root / "actual-cache"
            actual_cache.mkdir()
            linked_cache = root / "linked-cache"
            linked_cache.symlink_to(actual_cache, target_is_directory=True)
            completed = self.run_materializer(
                manifest=manifest,
                repository_root=root,
                builder=builder,
                cache_root=linked_cache,
                taxonomy_out=root / "taxonomy.jsonl",
                split_out=root / "split.json",
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("cache root must not be a symlink", completed.stderr)


if __name__ == "__main__":
    unittest.main()
