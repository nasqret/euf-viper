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
from contextlib import redirect_stderr
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "compare_commands_abba.py"
SPEC = importlib.util.spec_from_file_location("compare_commands_abba", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
COMPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPARE)


def write_manifest(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def command_arguments(flag: str, command: list[str]) -> list[str]:
    result: list[str] = []
    for token in command:
        result.extend([flag, token])
    return result


class ManifestAndCliValidationTests(unittest.TestCase):
    def test_manifest_order_hashes_and_declared_metadata_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first = root / "first.smt2"
            second = root / "second.smt2"
            first.write_bytes(b"sat\n")
            second.write_bytes(b"unsat\n")
            manifest = root / "manifest.jsonl"
            write_manifest(
                manifest,
                [
                    {
                        "id": 9,
                        "path": str(second),
                        "relative_path": "z/second.smt2",
                        "status": "unsat",
                        "bytes": second.stat().st_size,
                        "sha256": hashlib.sha256(second.read_bytes()).hexdigest(),
                    },
                    {
                        "id": "first",
                        "path": str(first),
                        "relative_path": "a/first.smt2",
                        "status": "sat",
                    },
                ],
            )

            rows = COMPARE.read_manifest(manifest)

            self.assertEqual(
                [row["relative_path"] for row in rows],
                ["z/second.smt2", "a/first.smt2"],
            )
            self.assertEqual(
                rows[0]["_file"]["sha256"],
                hashlib.sha256(b"unsat\n").hexdigest(),
            )

    def test_duplicate_resolved_paths_fail_even_with_different_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "case.smt2"
            source.write_text("sat\n", encoding="utf-8")
            alias = root / "alias.smt2"
            alias.symlink_to(source)
            manifest = root / "manifest.jsonl"
            write_manifest(
                manifest,
                [
                    {
                        "path": str(source),
                        "relative_path": "one.smt2",
                        "status": "sat",
                    },
                    {
                        "path": str(alias),
                        "relative_path": "two.smt2",
                        "status": "sat",
                    },
                ],
            )

            with self.assertRaisesRegex(
                COMPARE.BenchmarkInputError, "duplicate resolved path"
            ):
                COMPARE.read_manifest(manifest, limit=1)

    def test_command_template_requires_one_input_placeholder(self) -> None:
        with self.assertRaisesRegex(
            COMPARE.BenchmarkInputError, "exactly one literal"
        ):
            COMPARE.validate_command_template(["solver", "--fixed-arm"], "baseline")
        with self.assertRaisesRegex(
            COMPARE.BenchmarkInputError, "exactly one literal"
        ):
            COMPARE.validate_command_template(
                ["solver", "{input}", "--copy={input}"], "candidate"
            )
        self.assertEqual(
            COMPARE.validate_command_template(
                ["solver", "--input={input}"], "candidate"
            ),
            ["solver", "--input={input}"],
        )

    def test_nonfinite_timeout_is_rejected_before_execution(self) -> None:
        base = [
            "missing.jsonl",
            "--baseline-arg",
            sys.executable,
            "--baseline-arg",
            "{input}",
            "--candidate-arg",
            sys.executable,
            "--candidate-arg",
            "{input}",
            "--out",
            "unused.csv",
            "--summary",
            "unused.json",
        ]
        for value in ("nan", "inf", "-inf"):
            with (
                self.subTest(value=value),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                COMPARE.main([*base, f"--timeout={value}"])
            self.assertEqual(raised.exception.code, 2)

        with self.assertRaisesRegex(COMPARE.BenchmarkInputError, "finite positive"):
            COMPARE.run_argv([sys.executable], os.environ.copy(), float("nan"))


class CommandExecutionTests(unittest.TestCase):
    def test_stdout_accepts_only_one_exact_solver_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            script = Path(temp_dir) / "fake.py"
            script.write_text(
                "import sys\n"
                "outputs = {'good': 'unknown\\n', 'extra': 'sat\\nnoise\\n', "
                "'case': 'SAT\\n'}\n"
                "sys.stdout.write(outputs[sys.argv[1]])\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()

            good = COMPARE.run_argv(
                [sys.executable, str(script), "good"], environment, 1.0
            )
            extra = COMPARE.run_argv(
                [sys.executable, str(script), "extra"], environment, 1.0
            )
            wrong_case = COMPARE.run_argv(
                [sys.executable, str(script), "case"], environment, 1.0
            )

            self.assertEqual(good["result"], "unknown")
            self.assertIsNone(good["error_kind"])
            self.assertEqual(extra["result"], "invalid-output")
            self.assertEqual(extra["error_kind"], "invalid_stdout")
            self.assertEqual(wrong_case["error_kind"], "invalid_stdout")

    @unittest.skipUnless(os.name == "posix", "process-group semantics require POSIX")
    def test_timeout_kills_descendants_in_the_new_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            marker = root / "survived"
            script = root / "process_tree.py"
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

            observation = COMPARE.run_argv(
                [sys.executable, str(script), "parent", str(marker)],
                os.environ.copy(),
                0.10,
            )
            time.sleep(0.35)

            self.assertEqual(observation["result"], "timeout")
            self.assertEqual(observation["exit_code"], 124)
            self.assertTrue(observation["timed_out"])
            self.assertFalse(marker.exists())


class SummaryTests(unittest.TestCase):
    @staticmethod
    def sample(
        row_index: int,
        relative_path: str,
        label: str,
        repeat: int,
        result: str,
        elapsed: float,
        *,
        error_kind: str | None = None,
    ) -> dict:
        return {
            "row_index": row_index,
            "relative_path": relative_path,
            "label": label,
            "repeat": repeat,
            "result": result,
            "time_s": elapsed,
            "exit_code": 0,
            "process_returncode": 0,
            "timed_out": False,
            "error_kind": error_kind,
            "stdout": result,
            "stderr": "",
            "argv": [label, relative_path],
        }

    def test_common_speedups_and_accounting_use_per_path_medians(self) -> None:
        rows = [
            {"id": 0, "relative_path": "one.smt2", "status": "sat"},
            {"id": 1, "relative_path": "two.smt2", "status": "sat"},
        ]
        samples = [
            self.sample(0, "one.smt2", "baseline", 0, "sat", 4.0),
            self.sample(0, "one.smt2", "baseline", 1, "sat", 6.0),
            self.sample(0, "one.smt2", "candidate", 0, "sat", 2.0),
            self.sample(0, "one.smt2", "candidate", 1, "sat", 2.0),
            self.sample(1, "two.smt2", "baseline", 0, "sat", 8.0),
            self.sample(1, "two.smt2", "baseline", 1, "sat", 8.0),
            self.sample(1, "two.smt2", "candidate", 0, "unsat", 0.5),
            self.sample(
                1,
                "two.smt2",
                "candidate",
                1,
                "invalid-output",
                0.6,
                error_kind="invalid_stdout",
            ),
        ]

        summary = COMPARE.summarize(rows, samples, repeats=2)

        self.assertEqual(summary["baseline_correct"], 2)
        self.assertEqual(summary["candidate_correct"], 1)
        self.assertEqual(summary["coverage_delta"], -1)
        self.assertEqual(summary["common_correct_paths"], ["one.smt2"])
        self.assertAlmostEqual(summary["common_aggregate_speedup"], 2.5)
        self.assertAlmostEqual(summary["common_geometric_speedup"], 2.5)
        self.assertEqual(len(summary["wrong_answers"]), 1)
        self.assertEqual(len(summary["execution_errors"]), 1)
        self.assertEqual(summary["arms"]["candidate"]["wrong_runs"], 1)
        self.assertEqual(summary["arms"]["candidate"]["error_runs"], 1)


class EndToEndTests(unittest.TestCase):
    def test_fake_commands_preserve_manifest_order_and_abba_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first = root / "first.smt2"
            second = root / "second.smt2"
            first.write_text("sat\n", encoding="utf-8")
            second.write_text("unsat\n", encoding="utf-8")
            manifest = root / "manifest.jsonl"
            write_manifest(
                manifest,
                [
                    {
                        "id": "second",
                        "path": str(second),
                        "relative_path": "second.smt2",
                        "status": "unsat",
                    },
                    {
                        "id": "first",
                        "path": str(first),
                        "relative_path": "first.smt2",
                        "status": "sat",
                    },
                ],
            )
            log = root / "order.log"
            fake_solver = root / "fake_solver.py"
            fake_solver.write_text(
                "import sys\n"
                "from pathlib import Path\n"
                "label, log, source = sys.argv[1:]\n"
                "with Path(log).open('a', encoding='utf-8') as handle:\n"
                "    handle.write(f'{label}:{Path(source).name}\\n')\n"
                "print(Path(source).read_text(encoding='utf-8').strip())\n",
                encoding="utf-8",
            )
            baseline = [
                sys.executable,
                str(fake_solver),
                "baseline",
                str(log),
                "{input}",
            ]
            candidate = [
                sys.executable,
                str(fake_solver),
                "candidate",
                str(log),
                "{input}",
            ]
            output = root / "samples.csv"
            summary_path = root / "summary.json"
            arguments = [str(manifest)]
            arguments.extend(command_arguments("--baseline-arg", baseline))
            arguments.extend(command_arguments("--candidate-arg", candidate))
            arguments.extend(
                [
                    "--timeout",
                    "2",
                    "--repeats",
                    "2",
                    "--warmups",
                    "1",
                    "--out",
                    str(output),
                    "--summary",
                    str(summary_path),
                ]
            )

            exit_code = COMPARE.main(arguments)

            self.assertEqual(exit_code, 0)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                [
                    "baseline:second.smt2",
                    "candidate:second.smt2",
                    "baseline:second.smt2",
                    "candidate:second.smt2",
                    "candidate:second.smt2",
                    "baseline:second.smt2",
                    "candidate:first.smt2",
                    "baseline:first.smt2",
                    "candidate:first.smt2",
                    "baseline:first.smt2",
                    "baseline:first.smt2",
                    "candidate:first.smt2",
                ],
            )
            with output.open(newline="", encoding="utf-8") as handle:
                records = list(csv.DictReader(handle))
            self.assertEqual(len(records), 8)
            self.assertEqual(
                [record["label"] for record in records],
                [
                    "baseline",
                    "candidate",
                    "candidate",
                    "baseline",
                    "candidate",
                    "baseline",
                    "baseline",
                    "candidate",
                ],
            )
            self.assertEqual(
                [record["relative_path"] for record in records],
                ["second.smt2"] * 4 + ["first.smt2"] * 4,
            )

            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["manifest_order"], ["second.smt2", "first.smt2"])
            self.assertEqual(summary["baseline_correct"], 2)
            self.assertEqual(summary["candidate_correct"], 2)
            self.assertEqual(summary["common_correct"], 2)
            self.assertEqual(
                summary["manifest_sha256"], hashlib.sha256(manifest.read_bytes()).hexdigest()
            )
            self.assertEqual(
                summary["baseline_sha256"],
                hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(),
            )
            static_files = summary["artifacts"]["commands"]["baseline"][
                "static_file_arguments"
            ]
            self.assertIn(
                str(fake_solver.resolve()),
                {item["resolved_path"] for item in static_files},
            )
            self.assertEqual(
                [item["relative_path"] for item in summary["artifacts"]["input_files"]],
                ["second.smt2", "first.smt2"],
            )
            self.assertFalse(list(root.glob(".summary.json.*.tmp")))


if __name__ == "__main__":
    unittest.main()
