from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "compare_multiarm_williams.py"
SPEC = importlib.util.spec_from_file_location("compare_multiarm_williams", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
COMPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPARE)


def write_manifest(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def hashed_row(source: Path, relative_path: str, status: str) -> dict:
    content = source.read_bytes()
    return {
        "path": str(source),
        "relative_path": relative_path,
        "status": status,
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def arm_arguments(name: str, command: list[str], *environment: str) -> list[str]:
    arguments = ["--arm", name]
    for token in command:
        arguments.extend(["--arm-arg", token])
    for entry in environment:
        arguments.extend(["--arm-env", entry])
    return arguments


def observation(argv: list[str], result: str, elapsed: float) -> dict:
    error_kind = None
    if result == "invalid-output":
        error_kind = "invalid_stdout"
    return {
        "argv": argv,
        "result": result,
        "time_s": elapsed,
        "exit_code": 0,
        "process_returncode": 0,
        "timed_out": False,
        "error_kind": error_kind,
        "error_detail": None,
        "stdout": result + "\n",
        "stderr": "",
    }


class ScheduleBindingTests(unittest.TestCase):
    def test_execute_consumes_exact_versioned_schedule_and_records_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "case.smt2"
            source.write_text("sat\n", encoding="utf-8")
            manifest = root / "manifest.jsonl"
            write_manifest(manifest, [hashed_row(source, "case.smt2", "sat")])
            rows = COMPARE.read_hashed_manifest(manifest)
            arms = ["reference", "candidate", "third"]
            schedule = COMPARE.build_schedule(arms, repeats=6)
            output = root / "raw.csv"
            calls: list[str] = []

            def fake_run(
                template: list[str],
                input_path: str,
                environment: dict[str, str],
                timeout_s: float,
            ) -> dict:
                self.assertEqual(Path(input_path), source.resolve())
                self.assertEqual(timeout_s, 1.0)
                calls.append(template[1])
                return observation([*template[:-1], input_path], "sat", 0.01)

            templates = {arm: ["solver", arm, "{input}"] for arm in arms}
            environments = {arm: {} for arm in arms}
            with mock.patch.object(COMPARE, "run_command", side_effect=fake_run):
                samples = COMPARE.execute(
                    rows=rows,
                    schedule=schedule,
                    templates=templates,
                    environments=environments,
                    timeout_s=1.0,
                    output_csv=output,
                )

            expected_order = [
                arm
                for schedule_row in schedule["rows"]
                for arm in schedule_row["order"]
            ]
            self.assertEqual(calls, expected_order)
            self.assertEqual([sample["arm"] for sample in samples], expected_order)
            self.assertEqual(
                {sample["schedule_sha256"] for sample in samples},
                {COMPARE.canonical_json_sha256(schedule)},
            )
            self.assertTrue(all(sample["parser_inclusive"] for sample in samples))
            self.assertTrue(
                all(sample["timing_scope"] == COMPARE.TIMING_SCOPE for sample in samples)
            )
            with output.open(newline="", encoding="utf-8") as handle:
                records = list(csv.DictReader(handle))
            self.assertEqual([record["arm"] for record in records], expected_order)
            self.assertEqual(
                [int(record["arm_position"]) for record in records],
                [
                    position
                    for schedule_row in schedule["rows"]
                    for position in range(len(arms))
                ],
            )
            self.assertFalse(list(root.glob(".raw.csv.*.tmp")))

    def test_schedule_binding_rejects_incomplete_blocks_and_tampered_samples(self) -> None:
        with self.assertRaisesRegex(
            COMPARE.BenchmarkInputError, "positive multiple|cannot preserve"
        ):
            COMPARE.build_schedule(["a", "b", "c"], repeats=3)
        with self.assertRaisesRegex(COMPARE.BenchmarkInputError, "between 2 and 10"):
            COMPARE.build_schedule([f"arm-{index}" for index in range(11)])

        schedule = COMPARE.build_schedule(["a", "b"], repeats=2)
        rows = [{"relative_path": "case.smt2", "status": "sat"}]
        samples = complete_samples(rows, schedule)
        samples[0]["arm_position"] = 1 - samples[0]["arm_position"]
        samples[0]["order_in_repeat"] = samples[0]["arm_position"]
        with self.assertRaisesRegex(
            COMPARE.BenchmarkInputError, "not bound to the schedule"
        ):
            COMPARE.summarize(rows, samples, schedule)


class IntegrityAndCliTests(unittest.TestCase):
    def test_cli_records_manifest_source_executable_and_schedule_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "case.smt2"
            source.write_text("sat\n", encoding="utf-8")
            manifest = root / "manifest.jsonl"
            write_manifest(manifest, [hashed_row(source, "case.smt2", "sat")])
            solver = root / "solver.py"
            solver.write_text(
                "import os, sys\n"
                "from pathlib import Path\n"
                "label, source = sys.argv[1:]\n"
                "assert os.environ['BENCH_ARM'] == label\n"
                "print(Path(source).read_text(encoding='utf-8').strip())\n",
                encoding="utf-8",
            )
            output = root / "runs.csv"
            summary_path = root / "summary.json"
            arguments = [str(manifest)]
            arguments.extend(
                arm_arguments(
                    "reference",
                    [sys.executable, str(solver), "reference", "{input}"],
                    "BENCH_ARM=reference",
                )
            )
            arguments.extend(
                arm_arguments(
                    "candidate",
                    [sys.executable, str(solver), "candidate", "{input}"],
                    "BENCH_ARM=candidate",
                )
            )
            arguments.extend(
                [
                    "--repeats",
                    "2",
                    "--timeout",
                    "2",
                    "--out",
                    str(output),
                    "--summary",
                    str(summary_path),
                ]
            )

            with redirect_stdout(io.StringIO()):
                exit_code = COMPARE.main(arguments)

            self.assertEqual(exit_code, 0)
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
            executable_hash = hashlib.sha256(
                Path(sys.executable).resolve().read_bytes()
            ).hexdigest()
            solver_hash = hashlib.sha256(solver.read_bytes()).hexdigest()
            self.assertEqual(payload["manifest_sha256"], manifest_hash)
            self.assertEqual(payload["source_sha256"], {"case.smt2": source_hash})
            self.assertEqual(
                payload["executable_sha256"],
                {"candidate": executable_hash, "reference": executable_hash},
            )
            self.assertEqual(
                payload["schedule_sha256"],
                COMPARE.canonical_json_sha256(payload["schedule"]),
            )
            self.assertEqual(
                payload["schedule_binding"]["generator_sha256"],
                hashlib.sha256(Path(COMPARE.WILLIAMS.__file__).read_bytes()).hexdigest(),
            )
            for arm in ("reference", "candidate"):
                static_hashes = {
                    record["sha256"]
                    for record in payload["artifacts"]["commands"][arm][
                        "static_file_arguments"
                    ]
                }
                self.assertIn(solver_hash, static_hashes)
            self.assertEqual(
                payload["artifacts"]["results_csv"]["sha256"],
                hashlib.sha256(output.read_bytes()).hexdigest(),
            )
            self.assertEqual(
                payload["environment_overrides"],
                {
                    "candidate": {"BENCH_ARM": "candidate"},
                    "reference": {"BENCH_ARM": "reference"},
                },
            )
            self.assertEqual(payload["measured_runs"], 4)
            self.assertEqual(payload["common_correct"], 1)
            self.assertFalse(list(root.glob(".*.tmp")))

    def test_hashed_manifest_fails_closed_on_missing_or_wrong_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "case.smt2"
            source.write_text("sat\n", encoding="utf-8")
            manifest = root / "manifest.jsonl"
            row = hashed_row(source, "case.smt2", "sat")
            row.pop("sha256")
            write_manifest(manifest, [row])
            with self.assertRaisesRegex(
                COMPARE.BenchmarkInputError, "must declare source sha256"
            ):
                COMPARE.read_hashed_manifest(manifest)

            row["sha256"] = "0" * 64
            write_manifest(manifest, [row])
            with self.assertRaisesRegex(COMPARE.BenchmarkInputError, "SHA-256 mismatch"):
                COMPARE.read_hashed_manifest(manifest)

            other = root / "other.smt2"
            other.write_text("sat\n", encoding="utf-8")
            valid = hashed_row(source, "selected.smt2", "sat")
            unhashed = hashed_row(other, "unselected.smt2", "sat")
            unhashed.pop("sha256")
            write_manifest(manifest, [valid, unhashed])
            with self.assertRaisesRegex(
                COMPARE.BenchmarkInputError, "line 2 must declare source sha256"
            ):
                COMPARE.read_hashed_manifest(manifest, limit=1)

    def test_cli_validation_rejects_orphan_tokens_and_nonfinite_timeout(self) -> None:
        with (
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as orphaned,
        ):
            COMPARE.main(
                [
                    "missing.jsonl",
                    "--arm-arg",
                    sys.executable,
                    "--out",
                    "unused.csv",
                    "--summary",
                    "unused.json",
                ]
            )
        self.assertEqual(orphaned.exception.code, 2)

        base = [
            "missing.jsonl",
            "--arm",
            "a",
            "--arm-arg",
            sys.executable,
            "--arm-arg",
            "{input}",
            "--arm",
            "b",
            "--arm-arg",
            sys.executable,
            "--arm-arg",
            "{input}",
            "--out",
            "unused.csv",
            "--summary",
            "unused.json",
        ]
        for value in ("nan", "inf", "-inf", "0"):
            with (
                self.subTest(value=value),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                COMPARE.main([*base, f"--timeout={value}"])
            self.assertEqual(raised.exception.code, 2)

    def test_arm_validation_rejects_duplicates_missing_input_and_duplicate_env(self) -> None:
        valid_argv = [sys.executable, "{input}"]
        malformed = [
            (
                [
                    {"name": "same", "argv": valid_argv},
                    {"name": "same", "argv": valid_argv},
                ],
                "unique",
            ),
            (
                [
                    {"name": "a", "argv": [sys.executable]},
                    {"name": "b", "argv": valid_argv},
                ],
                "exactly one literal",
            ),
            (
                [
                    {
                        "name": "a",
                        "argv": valid_argv,
                        "env": ["MODE=one", "MODE=two"],
                    },
                    {"name": "b", "argv": valid_argv},
                ],
                "duplicate environment key",
            ),
        ]
        for specifications, message in malformed:
            with self.subTest(message=message), self.assertRaisesRegex(
                COMPARE.BenchmarkInputError, message
            ):
                COMPARE.prepare_arms(specifications)


class ProcessCleanupTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "process-group semantics require POSIX")
    def test_timeout_kills_the_complete_descendant_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            marker = root / "survived"
            script = root / "tree.py"
            script.write_text(
                "import subprocess, sys, time\n"
                "from pathlib import Path\n"
                "if sys.argv[1] == 'worker':\n"
                "    time.sleep(0.30)\n"
                "    Path(sys.argv[2]).write_text('alive', encoding='utf-8')\n"
                "else:\n"
                "    subprocess.Popen([sys.executable, __file__, 'worker', sys.argv[2]])\n"
                "    time.sleep(60)\n",
                encoding="utf-8",
            )

            result = COMPARE.run_argv(
                [sys.executable, str(script), "parent", str(marker)],
                os.environ.copy(),
                0.10,
            )
            time.sleep(0.35)

            self.assertEqual(result["result"], "timeout")
            self.assertEqual(result["exit_code"], 124)
            self.assertTrue(result["timed_out"])
            self.assertFalse(marker.exists())


def complete_samples(
    rows: list[dict],
    schedule: dict,
    *,
    result_by_arm_repeat: dict[tuple[str, int], str] | None = None,
) -> list[dict]:
    overrides = result_by_arm_repeat or {}
    samples: list[dict] = []
    sequence = 0
    for row_index, row in enumerate(rows):
        for repeat, record in enumerate(schedule["rows"]):
            for position, arm in enumerate(record["order"]):
                result = overrides.get((arm, repeat), row["status"])
                sample = {
                    "sequence": sequence,
                    "row_index": row_index,
                    "relative_path": row["relative_path"],
                    "expected_status": row["status"],
                    "arm": arm,
                    "label": arm,
                    "repeat": repeat,
                    "schedule_row": repeat,
                    "arm_position": position,
                    "order_in_repeat": position,
                    "schedule_order": list(record["order"]),
                    **observation([arm, row["relative_path"]], result, 1.0 + sequence),
                }
                samples.append(sample)
                sequence += 1
    return samples


class SummaryTests(unittest.TestCase):
    def test_wrong_answers_errors_and_summary_order_are_deterministic(self) -> None:
        rows = [{"id": 7, "relative_path": "case.smt2", "status": "sat"}]
        schedule = COMPARE.build_schedule(["reference", "candidate"], repeats=2)
        samples = complete_samples(
            rows,
            schedule,
            result_by_arm_repeat={
                ("candidate", 0): "unsat",
                ("candidate", 1): "invalid-output",
            },
        )

        forward = COMPARE.summarize(rows, samples, schedule)
        reverse = COMPARE.summarize(rows, list(reversed(samples)), schedule)

        self.assertEqual(forward, reverse)
        self.assertEqual(forward["accounting"]["wrong_answers"], 1)
        self.assertEqual(forward["accounting"]["execution_errors"], 1)
        self.assertEqual(forward["arms"]["candidate"]["wrong_runs"], 1)
        self.assertEqual(forward["arms"]["candidate"]["error_runs"], 1)
        self.assertEqual(forward["arms"]["reference"]["covered_paths"], 1)
        self.assertEqual(forward["arms"]["candidate"]["covered_paths"], 0)
        self.assertEqual(forward["common_correct"], 0)

        malformed = [dict(sample) for sample in samples]
        invalid = next(
            sample for sample in malformed if sample["result"] == "invalid-output"
        )
        invalid["error_kind"] = None
        with self.assertRaisesRegex(
            COMPARE.BenchmarkInputError, "unaccounted execution error"
        ):
            COMPARE.summarize(rows, malformed, schedule)

    def test_cli_returns_two_but_keeps_atomic_artifacts_for_wrong_answers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "case.smt2"
            source.write_text("sat\n", encoding="utf-8")
            manifest = root / "manifest.jsonl"
            write_manifest(manifest, [hashed_row(source, "case.smt2", "sat")])
            solver = root / "solver.py"
            solver.write_text(
                "import sys\n"
                "from pathlib import Path\n"
                "label, source = sys.argv[1:]\n"
                "print('unsat' if label == 'wrong' else "
                "Path(source).read_text(encoding='utf-8').strip())\n",
                encoding="utf-8",
            )
            output = root / "runs.csv"
            summary_path = root / "summary.json"
            arguments = [str(manifest)]
            arguments.extend(
                arm_arguments(
                    "reference",
                    [sys.executable, str(solver), "right", "{input}"],
                )
            )
            arguments.extend(
                arm_arguments(
                    "candidate",
                    [sys.executable, str(solver), "wrong", "{input}"],
                )
            )
            arguments.extend(
                [
                    "--repeats",
                    "2",
                    "--out",
                    str(output),
                    "--summary",
                    str(summary_path),
                ]
            )

            with redirect_stdout(io.StringIO()):
                exit_code = COMPARE.main(arguments)

            self.assertEqual(exit_code, 2)
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["accounting"]["wrong_answers"], 2)
            self.assertEqual(payload["arms"]["candidate"]["wrong_runs"], 2)
            self.assertTrue(output.is_file())
            self.assertTrue(summary_path.is_file())
            self.assertFalse(list(root.glob(".*.tmp")))


class SourceFormatTests(unittest.TestCase):
    def test_owned_files_are_ascii_only(self) -> None:
        for path in (SCRIPT, Path(__file__)):
            with self.subTest(path=path):
                path.read_bytes().decode("ascii")


if __name__ == "__main__":
    unittest.main()
