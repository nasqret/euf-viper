from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "collect_eq_abstraction_shadow.py"
SPEC = importlib.util.spec_from_file_location("collect_eq_abstraction_shadow", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
COLLECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECTOR)


FAKE_VIPER = r"""#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

if len(sys.argv) != 4 or sys.argv[1:3] != ["solve", "--stats"]:
    print("expected: solve --stats FILE", file=sys.stderr)
    raise SystemExit(64)
if os.environ.get("EUF_VIPER_EQ_ABSTRACTION") != "shadow":
    print("shadow mode was not forced", file=sys.stderr)
    raise SystemExit(65)
if os.environ.get("EUF_VIPER_PROFILE") != "1":
    print("profiling was not forced", file=sys.stderr)
    raise SystemExit(66)

payload = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
mode = payload.get("mode", "ok")
if mode == "timeout":
    time.sleep(payload.get("sleep", 2.0))
    raise SystemExit(0)
if mode == "failure":
    print("synthetic solver failure", file=sys.stderr)
    raise SystemExit(payload.get("exit_code", 7))

values = {
    "star_edges": payload.get("star_edges", 0),
    "nodes": payload.get("nodes", 10),
    "memo_entries": payload.get("memo_entries", 8),
    "memo_hits": payload.get("memo_hits", 2),
    "work": payload.get("work", 20),
    "classes": payload.get("classes", 3),
    "partition_terms": payload.get("partition_terms", 5),
}
print(payload.get("result", "sat"))
print(
    f"profile_eq_abstraction_ns={payload.get('eq_ns', 5)} "
    f"count={values['star_edges']}",
    file=sys.stderr,
)
for label, field in [
    ("nodes", "nodes"),
    ("memo_entries", "memo_entries"),
    ("memo_hits", "memo_hits"),
    ("work", "work"),
    ("classes", "classes"),
    ("partition_terms", "partition_terms"),
]:
    if mode == "malformed" and label == "partition_terms":
        continue
    print(
        f"profile_eq_abstraction_{label}_ns=0 count={values[field]}",
        file=sys.stderr,
    )
print(
    "profile_eq_abstraction_mode=shadow "
    f"cap_reason={payload.get('cap_reason', 'none')} "
    f"infeasible={int(payload.get('infeasible', False))}",
    file=sys.stderr,
)
print(f"elapsed_ns={payload.get('elapsed_ns', 100)}", file=sys.stderr)
"""


def valid_profile() -> str:
    return "\n".join(
        [
            "profile_parse_ns=11 count=3",
            "profile_eq_abstraction_ns=17 count=2",
            "profile_eq_abstraction_nodes_ns=0 count=19",
            "profile_eq_abstraction_memo_entries_ns=0 count=7",
            "profile_eq_abstraction_memo_hits_ns=0 count=5",
            "profile_eq_abstraction_work_ns=0 count=23",
            "profile_eq_abstraction_classes_ns=0 count=3",
            "profile_eq_abstraction_partition_terms_ns=0 count=11",
            "profile_eq_abstraction_mode=shadow cap_reason=none infeasible=0",
            "elapsed_ns=101",
        ]
    )


def success_record(
    relative_path: str,
    *,
    manifest_line: int = 1,
    star_edges: int = 0,
    cap_reason: str = "none",
    eq_ns: int = 5,
    elapsed_ns: int = 100,
    wall_ns: int = 120,
    infeasible: bool = False,
) -> dict:
    return {
        "schema_version": 1,
        "id": manifest_line,
        "manifest_line": manifest_line,
        "relative_path": relative_path,
        "resolved_path": f"/corpus/{relative_path}",
        "expected_status": "sat",
        "status": "ok",
        "solver_result": "sat",
        "exit_code": 0,
        "wall_time_ns": wall_ns,
        "eq_abstraction_ns": eq_ns,
        "solver_elapsed_ns": elapsed_ns,
        "star_edges": star_edges,
        "nodes": 10,
        "memo_entries": 8,
        "memo_hits": 2,
        "work": 20,
        "classes": 3,
        "partition_terms": 5,
        "cap_reason": cap_reason,
        "infeasible": infeasible,
    }


def timeout_record(relative_path: str, *, manifest_line: int = 1) -> dict:
    return {
        "schema_version": 1,
        "id": manifest_line,
        "manifest_line": manifest_line,
        "relative_path": relative_path,
        "resolved_path": f"/corpus/{relative_path}",
        "expected_status": "sat",
        "status": "timeout",
        "failure_kind": "timeout",
        "message": "timed out",
        "exit_code": 124,
        "wall_time_ns": 200,
    }


class ProfileParserTests(unittest.TestCase):
    def test_parses_complete_c958c9e_profile(self) -> None:
        parsed = COLLECTOR.parse_profile(valid_profile())

        self.assertEqual(
            parsed,
            {
                "eq_abstraction_ns": 17,
                "solver_elapsed_ns": 101,
                "star_edges": 2,
                "nodes": 19,
                "memo_entries": 7,
                "memo_hits": 5,
                "work": 23,
                "classes": 3,
                "partition_terms": 11,
                "cap_reason": "none",
                "infeasible": False,
            },
        )

    def test_rejects_missing_duplicate_and_malformed_profile_records(self) -> None:
        valid = valid_profile()
        malformed = [
            valid.replace(
                "profile_eq_abstraction_partition_terms_ns=0 count=11\n", ""
            ),
            valid + "\nprofile_eq_abstraction_nodes_ns=0 count=19",
            valid.replace("memo_hits_ns=0 count=5", "memo_hits_ns=0 count=-1"),
            valid.replace("nodes_ns=0 count=19", "nodes_ns=1 count=19"),
            valid.replace("mode=shadow", "mode=facts"),
            valid.replace("cap_reason=none", "cap_reason=unexpected"),
            valid.replace("elapsed_ns=101", "elapsed_ns=bad"),
        ]

        for profile in malformed:
            with self.subTest(profile=profile):
                with self.assertRaises(COLLECTOR.ProfileOutputError):
                    COLLECTOR.parse_profile(profile)


class ManifestAndTelemetryValidationTests(unittest.TestCase):
    def test_rejects_malformed_manifest_rows(self) -> None:
        cases = [
            "not json\n",
            json.dumps({"relative_path": "../escape.smt2"}) + "\n",
            json.dumps({"relative_path": "same.smt2"})
            + "\n"
            + json.dumps({"relative_path": "same.smt2"})
            + "\n",
            json.dumps({"relative_path": "ok.smt2", "path": 12}) + "\n",
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = Path(temp_dir) / "manifest.jsonl"
            for content in cases:
                with self.subTest(content=content):
                    manifest.write_text(content, encoding="utf-8")
                    with self.assertRaises(COLLECTOR.ManifestError):
                        COLLECTOR.read_manifest(manifest)

    def test_rejects_malformed_telemetry_records(self) -> None:
        missing_metric = success_record("a.smt2")
        del missing_metric["memo_hits"]
        bad_timeout = timeout_record("b.smt2")
        bad_timeout["status"] = "failure"

        for record in [missing_metric, bad_timeout, ["not", "an", "object"]]:
            with self.subTest(record=record):
                with self.assertRaises(COLLECTOR.TelemetryError):
                    COLLECTOR.validate_telemetry_record(record, "test")


class CollectorCliTests(unittest.TestCase):
    def test_classifies_failures_and_timeouts_and_writes_sorted_outputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="eq shadow collector ") as temp_dir:
            base = Path(temp_dir)
            benchmark_root = base / "benchmark root"
            binary = base / "tools" / "fake euf-viper"
            manifest = base / "manifest.jsonl"
            output = base / "telemetry.jsonl"
            summary_path = base / "summary.json"
            binary.parent.mkdir(parents=True)
            binary.write_text(FAKE_VIPER, encoding="utf-8")
            binary.chmod(0o755)

            cases = {
                "z/hit.smt2": {
                    "star_edges": 4,
                    "cap_reason": "work",
                    "eq_ns": 15,
                    "elapsed_ns": 300,
                    "infeasible": True,
                },
                "a/ok.smt2": {"eq_ns": 5, "elapsed_ns": 100},
                "b/timeout.smt2": {"mode": "timeout"},
                "c/failure.smt2": {"mode": "failure", "exit_code": 7},
                "d/malformed.smt2": {"mode": "malformed"},
            }
            rows = []
            for index, (relative_path, payload) in enumerate(cases.items()):
                path = benchmark_root.joinpath(*Path(relative_path).parts)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(payload), encoding="utf-8")
                rows.append(
                    {
                        "id": index,
                        "relative_path": relative_path,
                        "path": f"/stale/root/{relative_path}",
                        "status": "sat",
                    }
                )
            manifest.write_text(
                "".join(json.dumps(row) + "\n" for row in reversed(rows)),
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "collect",
                    str(manifest),
                    "--binary",
                    str(binary),
                    "--benchmark-root",
                    str(benchmark_root),
                    "--timeout",
                    "1",
                    "--jobs",
                    "3",
                    "--out",
                    str(output),
                    "--summary",
                    str(summary_path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("successful=2 failed=3 timeouts=1", completed.stdout)
            records = [
                json.loads(line)
                for line in output.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                [record["relative_path"] for record in records], sorted(cases)
            )
            failures = {
                record["relative_path"]: record["failure_kind"]
                for record in records
                if record["status"] != "ok"
            }
            self.assertEqual(
                failures,
                {
                    "b/timeout.smt2": "timeout",
                    "c/failure.smt2": "nonzero_exit",
                    "d/malformed.smt2": "malformed_profile",
                },
            )

            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(
                summary["counts"],
                {
                    "manifest_instances": 5,
                    "successful_instances": 2,
                    "failed_instances": 3,
                    "timeout_instances": 1,
                    "star_edge_hit_instances": 1,
                    "capped_instances": 1,
                    "infeasible_instances": 1,
                },
            )
            self.assertEqual(summary["star_edges"]["hit_paths"], ["z/hit.smt2"])
            self.assertEqual(summary["caps"]["counts"], {"work": 1})
            self.assertEqual(
                summary["failures"]["counts"],
                {"malformed_profile": 1, "nonzero_exit": 1, "timeout": 1},
            )
            self.assertEqual(
                summary["aggregate_overhead"]["eq_abstraction_ns"], 20
            )
            self.assertEqual(
                summary["aggregate_overhead"]["solver_elapsed_ns"], 400
            )
            self.assertEqual(
                summary["aggregate_overhead"][
                    "eq_abstraction_fraction_of_solver_elapsed"
                ],
                0.05,
            )


class SummaryAndMergeTests(unittest.TestCase):
    def test_summary_is_deterministic_for_any_record_order(self) -> None:
        records = [
            timeout_record("m/timeout.smt2", manifest_line=3),
            success_record(
                "z/hit.smt2",
                manifest_line=2,
                star_edges=3,
                cap_reason="entries",
                eq_ns=20,
                elapsed_ns=200,
            ),
            success_record(
                "a/ok.smt2", manifest_line=1, eq_ns=10, elapsed_ns=100
            ),
        ]
        source = {"mode": "test", "manifest": "manifest.jsonl"}

        first = COLLECTOR.build_summary(records, source)
        second = COLLECTOR.build_summary(list(reversed(records)), source)

        self.assertEqual(first, second)
        self.assertEqual(first["star_edges"]["hit_paths"], ["z/hit.smt2"])
        self.assertEqual(
            first["caps"]["paths_by_reason"], {"entries": ["z/hit.smt2"]}
        )
        self.assertEqual(
            first["failures"]["paths_by_kind"],
            {"timeout": ["m/timeout.smt2"]},
        )
        self.assertEqual(
            first["aggregate_overhead"][
                "eq_abstraction_fraction_of_solver_elapsed"
            ],
            0.1,
        )

    def test_merge_is_complete_and_normalizes_full_manifest_lines(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            manifest = base / "manifest.jsonl"
            first_shard = base / "first.jsonl"
            second_shard = base / "second.jsonl"
            manifest.write_text(
                json.dumps(
                    {
                        "id": 2,
                        "relative_path": "z.smt2",
                        "path": "/corpus/z.smt2",
                        "status": "sat",
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "id": 1,
                        "relative_path": "a.smt2",
                        "path": "/corpus/a.smt2",
                        "status": "sat",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            a_record = success_record("a.smt2", manifest_line=1)
            a_record["id"] = 1
            z_record = timeout_record("z.smt2", manifest_line=1)
            z_record["id"] = 2
            first_shard.write_text(json.dumps(z_record) + "\n", encoding="utf-8")
            second_shard.write_text(json.dumps(a_record) + "\n", encoding="utf-8")

            merged = COLLECTOR.merge_shards(manifest, [first_shard, second_shard])

            self.assertEqual(
                [record["relative_path"] for record in merged], ["a.smt2", "z.smt2"]
            )
            self.assertEqual(
                [record["manifest_line"] for record in merged], [2, 1]
            )
            with self.assertRaises(COLLECTOR.TelemetryError):
                COLLECTOR.merge_shards(manifest, [first_shard])


if __name__ == "__main__":
    unittest.main()
