from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "compare_rollback_control.py"
SPEC = importlib.util.spec_from_file_location("compare_rollback_control", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
COMPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPARE)


FAKE_SOLVER = r"""
#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

if len(sys.argv) != 4 or sys.argv[1:3] != ["solve", "--stats"]:
    raise SystemExit(64)
if "EUF_VIPER_LEAK_ME" in os.environ:
    print("ambient EUF variable leaked", file=sys.stderr)
    raise SystemExit(65)
case = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
backend = os.environ.get("EUF_VIPER_BACKEND")
label = "candidate" if backend == "cadical-rollback" else "baseline"
log = os.environ.get("ORDER_LOG")
if log:
    with Path(log).open("a", encoding="utf-8") as handle:
        handle.write(f"{Path(sys.argv[3]).name}:{label}\n")
mode = case.get("mode", "normal")
if mode == "timeout":
    time.sleep(1.0)
if mode == "unsupported":
    print("unsupported")
    raise SystemExit(3)
result = case.get("result", case["status"])
print(result)
if label == "baseline":
    print("profile_kissat_validation_ns=10 count=1", file=sys.stderr)
    print("profile_kissat_validation_ns=20 count=2", file=sys.stderr)
else:
    print("profile_cadical_rollback_complete_validations_ns=7 count=1", file=sys.stderr)
    print("profile_cadical_rollback_conflicts_ns=0 count=2", file=sys.stderr)
    print("profile_cadical_rollback_propagator_model_checks_ns=5 count=1", file=sys.stderr)
print("sat_calls=4", file=sys.stderr)
print("theory_lemmas=2", file=sys.stderr)
"""


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def write_executable(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(0o755)


def write_case(
    root: Path,
    name: str,
    status: str,
    control_class: str,
    mode: str = "normal",
) -> dict:
    source = root / name
    payload = json.dumps({"mode": mode, "status": status}, sort_keys=True) + "\n"
    source.write_text(payload, encoding="utf-8")
    data = source.read_bytes()
    return {
        "bytes": len(data),
        "path": str(source),
        "relative_path": f"QF_UF/tests/{name}",
        "sha256": digest(data),
        "status": status,
        "control_class": control_class,
    }


def write_manifest(path: Path, rows: list[dict]) -> None:
    path.write_bytes(b"".join(COMPARE.canonical_bytes(row) for row in rows))


class RollbackControlComparatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="rollback compare ")
        self.root = Path(self.temp_dir.name)
        self.solver = self.root / "fake-solver"
        write_executable(self.solver, FAKE_SOLVER)
        self.rows = [
            write_case(self.root, "target.smt2", "unsat", "target"),
            write_case(self.root, "anti.smt2", "sat", "anti-target"),
        ]
        self.manifest = self.root / "manifest.jsonl"
        write_manifest(self.manifest, self.rows)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def run_compare(
        self,
        comparison: str,
        *,
        manifest: Path | None = None,
        repeats: int = 2,
        timeout: float = 1.0,
        shard_index: int = 0,
        shard_count: int = 1,
        suffix: str = "",
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        journal = self.root / f"{comparison}{suffix}.jsonl"
        summary = self.root / f"{comparison}{suffix}.summary.json"
        environment = {
            **os.environ,
            "EUF_VIPER_LEAK_ME": "must-be-removed",
            "ORDER_LOG": str(self.root / "order.log"),
        }
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(manifest or self.manifest),
                "--binary",
                str(self.solver),
                "--comparison",
                comparison,
                "--timeout",
                str(timeout),
                "--repeats",
                str(repeats),
                "--shard-index",
                str(shard_index),
                "--shard-count",
                str(shard_count),
                "--out",
                str(journal),
                "--summary",
                str(summary),
            ],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        return completed, journal, summary

    def test_abba_environment_cleaning_hash_chain_and_profile_accumulation(self) -> None:
        completed, journal, summary_path = self.run_compare("current")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        records = [json.loads(line) for line in journal.read_text().splitlines()]
        plan, observations = records[0], records[1:]
        self.assertEqual(plan["order"], "ABBA")
        self.assertEqual(
            set(plan["cpu_affinity"]),
            {"cpu_ids", "expected_cpu_ids", "mechanism", "single_cpu_required"},
        )
        self.assertIn("EUF_VIPER_LEAK_ME", plan["removed_ambient_euf_viper"])
        self.assertEqual(plan["solver_environment"]["candidate"], {
            "EUF_VIPER_BACKEND": "cadical-rollback",
            "EUF_VIPER_PROFILE": "1",
        })
        self.assertEqual(len(observations), 8)
        for offset in (0, 4):
            self.assertEqual(
                [row["label"] for row in observations[offset : offset + 4]],
                ["baseline", "candidate", "candidate", "baseline"],
            )
        baseline = next(row for row in observations if row["label"] == "baseline")
        self.assertEqual(
            baseline["profile"]["kissat_validation"],
            {"elapsed_ns": 30, "count": 3},
        )
        self.assertTrue(all(row["outcome"] == "correct" for row in observations))
        previous = None
        for record in records:
            self.assertEqual(record["previous_record_sha256"], previous)
            self.assertEqual(COMPARE.record_hash(record), record["record_hash"])
            previous = record["record_hash"]

        summary = json.loads(summary_path.read_text())
        expected_summary_hash = summary["summary_sha256"]
        summary["summary_sha256"] = ""
        self.assertEqual(expected_summary_hash, digest(COMPARE.canonical_bytes(summary)))
        self.assertEqual(summary["journal_record_chain_head"], records[-1]["record_hash"])

    def test_explicit_configs_and_modulo_sharding_are_bound(self) -> None:
        for comparison in COMPARE.COMPARISONS:
            with self.subTest(comparison=comparison):
                completed, journal, _ = self.run_compare(
                    comparison,
                    repeats=2,
                    shard_index=1,
                    shard_count=2,
                    suffix="-shard",
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                records = [json.loads(line) for line in journal.read_text().splitlines()]
                plan, observations = records[0], records[1:]
                self.assertEqual(plan["selected_rows"], 1)
                self.assertEqual(plan["shard"]["mechanism"], "manifest-index-modulo")
                self.assertEqual(
                    plan["solver_environment"]["baseline"],
                    {**COMPARE.BASELINE_CONFIGS[comparison], "EUF_VIPER_PROFILE": "1"},
                )
                self.assertEqual(
                    {row["relative_path"] for row in observations},
                    {self.rows[1]["relative_path"]},
                )

    def test_timeout_and_unsupported_are_coverage_misses(self) -> None:
        rows = [
            write_case(self.root, "unsupported.smt2", "sat", "target", "unsupported"),
            write_case(self.root, "timeout.smt2", "unsat", "anti-target", "timeout"),
        ]
        manifest = self.root / "misses.jsonl"
        write_manifest(manifest, rows)
        completed, journal, summary = self.run_compare(
            "current",
            manifest=manifest,
            repeats=2,
            timeout=0.2,
            suffix="-misses",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        observations = [json.loads(line) for line in journal.read_text().splitlines()[1:]]
        by_path = {}
        for observation in observations:
            by_path.setdefault(observation["relative_path"], []).append(observation)
        unsupported = by_path[rows[0]["relative_path"]]
        timed_out = by_path[rows[1]["relative_path"]]
        self.assertTrue(all(row["result"] == "unsupported" for row in unsupported))
        self.assertTrue(all(row["exit_code"] == 3 for row in unsupported))
        self.assertTrue(all(row["outcome"] == "coverage_miss" for row in unsupported))
        self.assertTrue(all(row["result"] == "timeout" for row in timed_out))
        self.assertTrue(all(row["timed_out"] for row in timed_out))
        self.assertTrue(all(row["outcome"] == "coverage_miss" for row in timed_out))
        payload = json.loads(summary.read_text())
        self.assertEqual(payload["outcomes"]["baseline"], {"coverage_miss": 4})
        self.assertEqual(payload["outcomes"]["candidate"], {"coverage_miss": 4})

    def test_odd_repeat_count_is_rejected_before_execution(self) -> None:
        completed, journal, summary = self.run_compare(
            "current", repeats=1, suffix="-odd"
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("positive even count", completed.stderr)
        self.assertFalse(journal.exists())
        self.assertFalse(summary.exists())

    def test_cpu_affinity_can_be_bound_to_an_exact_singleton(self) -> None:
        with mock.patch.object(
            COMPARE.os, "sched_getaffinity", return_value={7}, create=True
        ):
            self.assertEqual(
                COMPARE.bind_cpu_affinity(
                    expected_cpu_ids=[7], require_single_cpu=True
                ),
                {
                    "cpu_ids": [7],
                    "expected_cpu_ids": [7],
                    "mechanism": "sched_getaffinity",
                    "single_cpu_required": True,
                },
            )
            with self.assertRaises(COMPARE.CompareError):
                COMPARE.bind_cpu_affinity(
                    expected_cpu_ids=[8], require_single_cpu=True
                )


if __name__ == "__main__":
    unittest.main()
