from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "build_pgo_split.py"
SPEC = importlib.util.spec_from_file_location("build_pgo_split", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SPLITTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SPLITTER)


def row(identifier: int, family: str, case: int) -> dict[str, object]:
    return {
        "bytes": 100 + case,
        "id": identifier,
        "logic": "QF_UF",
        "path": f"/stale/corpus/QF_UF/{family}/case-{case}.smt2",
        "relative_path": f"QF_UF/{family}/case-{case}.smt2",
        "sha256": hashlib.sha256(f"{family}-{case}".encode()).hexdigest(),
        "status": "sat" if case % 2 else "unsat",
    }


def fixture_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    identifier = 1
    for case in range(4):
        for family in ("alpha", "beta", "gamma", "holdout"):
            rows.append(row(identifier, family, case))
            identifier += 1
    return rows


def write_manifest(path: Path, rows: list[dict[str, object]]) -> Path:
    path.write_bytes(b"".join(SPLITTER.canonical_json_bytes(item) for item in rows))
    return path


class SplitConstructionTests(unittest.TestCase):
    def test_rebased_split_rewrites_both_outputs_and_binds_definition(self) -> None:
        training, holdout, report = SPLITTER.construct_split(
            fixture_rows(),
            seed="test-seed",
            holdout_modulus=5,
            holdout_residue=0,
            explicit_holdout_families=["holdout"],
            max_train_per_family=1,
            rebase_root="/wmi/read-only/corpus",
        )
        for item in [*training, *holdout]:
            self.assertEqual(
                item["path"],
                "/wmi/read-only/corpus/" + item["relative_path"],
            )
        self.assertEqual(
            report["definition"]["path_rewrite"],
            {"mode": "rebased", "rebase_root": "/wmi/read-only/corpus"},
        )

    def test_rebase_root_must_be_canonical_absolute_posix_path(self) -> None:
        for root in (
            "relative",
            "/",
            "//server/share",
            "/work/../corpus",
            "/work//corpus",
            "/work/corpus/",
            "/work\\corpus",
        ):
            with self.subTest(root=root):
                with self.assertRaises(SPLITTER.SplitError):
                    SPLITTER.construct_split(
                        fixture_rows(),
                        seed="test-seed",
                        holdout_modulus=5,
                        holdout_residue=0,
                        explicit_holdout_families=["holdout"],
                        max_train_per_family=1,
                        rebase_root=root,
                    )

    def test_training_size_cap_is_bound_and_can_remove_large_families(self) -> None:
        training, holdout, report = SPLITTER.construct_split(
            fixture_rows(),
            seed="test-seed",
            holdout_modulus=5,
            holdout_residue=0,
            explicit_holdout_families=["holdout"],
            max_train_per_family=4,
            max_train_source_bytes=101,
        )
        self.assertEqual(len(training), 6)
        self.assertTrue(all(item["bytes"] <= 101 for item in training))
        self.assertEqual(len(holdout), 4)
        self.assertEqual(report["definition"]["max_train_source_bytes"], 101)
        with self.assertRaisesRegex(SPLITTER.SplitError, "both training"):
            SPLITTER.construct_split(
                fixture_rows(),
                seed="test-seed",
                holdout_modulus=5,
                holdout_residue=0,
                explicit_holdout_families=["holdout"],
                max_train_per_family=4,
                max_train_source_bytes=1,
            )
        for cap in (0, -1, True):
            with self.subTest(cap=cap):
                with self.assertRaises(SPLITTER.SplitError):
                    SPLITTER.construct_split(
                        fixture_rows(),
                        seed="test-seed",
                        holdout_modulus=5,
                        holdout_residue=0,
                        explicit_holdout_families=["holdout"],
                        max_train_per_family=4,
                        max_train_source_bytes=cap,
                    )

    def test_explicit_split_is_deterministic_bounded_and_family_disjoint(self) -> None:
        rows = fixture_rows()
        arguments = {
            "seed": "test-seed",
            "holdout_modulus": 5,
            "holdout_residue": 0,
            "explicit_holdout_families": ["holdout"],
            "max_train_per_family": 2,
        }
        first = SPLITTER.construct_split(rows, **arguments)
        second = SPLITTER.construct_split(rows, **arguments)
        self.assertEqual(first, second)

        training, holdout, report = first
        training_families = {
            SPLITTER.family_of(item["relative_path"]) for item in training
        }
        holdout_families = {
            SPLITTER.family_of(item["relative_path"]) for item in holdout
        }
        self.assertEqual(training_families, {"alpha", "beta", "gamma"})
        self.assertEqual(holdout_families, {"holdout"})
        self.assertFalse(training_families & holdout_families)
        self.assertEqual(len(training), 6)
        self.assertEqual(len(holdout), 4)
        self.assertEqual(report["counts"]["unselected_training_family_rows"], 6)
        self.assertTrue(report["family_disjoint"])

    def test_invalid_split_definitions_fail_closed(self) -> None:
        rows = fixture_rows()
        base = {
            "seed": "seed",
            "holdout_modulus": 5,
            "holdout_residue": 0,
            "explicit_holdout_families": ["holdout"],
            "max_train_per_family": 2,
        }
        variants = (
            {"seed": ""},
            {"holdout_modulus": 1},
            {"holdout_residue": 5},
            {"max_train_per_family": 0},
            {"explicit_holdout_families": ["missing"]},
            {"explicit_holdout_families": ["holdout", "holdout"]},
            {
                "explicit_holdout_families": [
                    "alpha",
                    "beta",
                    "gamma",
                    "holdout",
                ]
            },
        )
        for update in variants:
            with self.subTest(update=update):
                arguments = {**base, **update}
                with self.assertRaises(SPLITTER.SplitError):
                    SPLITTER.construct_split(rows, **arguments)


class ManifestValidationTests(unittest.TestCase):
    def test_valid_manifest_preserves_rows_and_raw_hash(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pgo split valid ") as temp:
            path = write_manifest(Path(temp) / "full.jsonl", fixture_rows())
            loaded, sha256 = SPLITTER.load_manifest(path)
            self.assertEqual(loaded, fixture_rows())
            self.assertEqual(sha256, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_jsonl_and_field_damage_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pgo split invalid ") as temp:
            root = Path(temp)
            valid = fixture_rows()[0]
            cases: dict[str, bytes] = {
                "empty": b"",
                "blank": SPLITTER.canonical_json_bytes(valid) + b"\n",
                "malformed": b'{"id":1,\n',
                "non-object": b"[]\n",
                "duplicate-key": b'{"id":1,"id":2}\n',
                "non-finite": b'{"id":NaN}\n',
                "invalid-utf8": b"\xff\n",
            }
            for name, data in cases.items():
                with self.subTest(name=name):
                    path = root / f"{name}.jsonl"
                    path.write_bytes(data)
                    with self.assertRaises(SPLITTER.SplitError):
                        SPLITTER.load_manifest(path)

            variants: list[tuple[str, dict[str, object]]] = []
            missing = dict(valid)
            missing.pop("sha256")
            variants.append(("missing", missing))
            for name, field, value in (
                ("bool-id", "id", True),
                ("empty-id", "id", ""),
                ("list-id", "id", []),
                ("logic", "logic", "QF_LIA"),
                ("list-status", "status", ["sat"]),
                ("status", "status", "unknown"),
                ("bool-bytes", "bytes", True),
                ("negative-bytes", "bytes", -1),
                ("short-hash", "sha256", "0" * 63),
                ("path-traversal", "relative_path", "QF_UF/family/../x.smt2"),
                ("backslash", "relative_path", "QF_UF/family\\x/case.smt2"),
            ):
                damaged = dict(valid)
                damaged[field] = value
                variants.append((name, damaged))
            for name, damaged in variants:
                with self.subTest(name=name):
                    path = write_manifest(root / f"field-{name}.jsonl", [damaged])
                    with self.assertRaises(SPLITTER.SplitError):
                        SPLITTER.load_manifest(path)

    def test_duplicate_ids_and_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pgo split duplicate ") as temp:
            root = Path(temp)
            rows = fixture_rows()[:2]
            duplicate_id = dict(rows[1])
            duplicate_id["id"] = rows[0]["id"]
            duplicate_path = dict(rows[1])
            duplicate_path["relative_path"] = rows[0]["relative_path"]
            for name, duplicate in (
                ("id", duplicate_id),
                ("path", duplicate_path),
            ):
                with self.subTest(name=name):
                    path = write_manifest(root / f"{name}.jsonl", [rows[0], duplicate])
                    with self.assertRaises(SPLITTER.SplitError):
                        SPLITTER.load_manifest(path)


class ArtifactAndCliTests(unittest.TestCase):
    def test_cli_outputs_are_byte_deterministic_and_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pgo split cli ") as temp:
            root = Path(temp)
            manifest = write_manifest(root / "full.jsonl", fixture_rows())
            outputs: list[tuple[bytes, bytes, bytes]] = []
            for label in ("first", "second"):
                target = root / label
                train = target / "train.jsonl"
                holdout = target / "holdout.jsonl"
                report = target / "report.json"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT),
                        str(manifest),
                        "--train-out",
                        str(train),
                        "--holdout-out",
                        str(holdout),
                        "--report-out",
                        str(report),
                        "--holdout-family",
                        "holdout",
                        "--max-train-per-family",
                        "2",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("training=6 holdout=4", completed.stdout)
                outputs.append((train.read_bytes(), holdout.read_bytes(), report.read_bytes()))

            self.assertEqual(outputs[0], outputs[1])
            train_data, holdout_data, report_data = outputs[0]
            report = json.loads(report_data)
            self.assertEqual(
                report["outputs"]["training_manifest_sha256"],
                hashlib.sha256(train_data).hexdigest(),
            )
            self.assertEqual(
                report["outputs"]["holdout_manifest_sha256"],
                hashlib.sha256(holdout_data).hexdigest(),
            )

    def test_staging_failure_preserves_existing_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pgo split atomic ") as temp:
            root = Path(temp)
            first = root / "train.jsonl"
            first.write_bytes(b"old\n")
            blocker = root / "blocker"
            blocker.write_bytes(b"not a directory\n")
            with self.assertRaises(OSError):
                SPLITTER.write_artifacts_atomic(
                    ((first, b"new\n"), (blocker / "holdout.jsonl", b"new\n"))
                )
            self.assertEqual(first.read_bytes(), b"old\n")
            self.assertEqual(list(root.glob(".train.jsonl.*")), [])

    def test_cli_rejects_overwriting_the_input_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pgo split overwrite ") as temp:
            root = Path(temp)
            manifest = write_manifest(root / "full.jsonl", fixture_rows())
            before = manifest.read_bytes()
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(manifest),
                    "--train-out",
                    str(manifest),
                    "--holdout-out",
                    str(root / "holdout.jsonl"),
                    "--report-out",
                    str(root / "report.json"),
                    "--holdout-family",
                    "holdout",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("must not overwrite", completed.stderr)
            self.assertEqual(manifest.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
