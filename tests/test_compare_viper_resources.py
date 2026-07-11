from __future__ import annotations

import csv
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "compare_viper_resources.py"
SPEC = importlib.util.spec_from_file_location("compare_viper_resources", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
COMPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPARE)


FAKE_TIME = r"""
#!/usr/bin/env python3
import os
import subprocess
import sys
import time
from pathlib import Path

args = sys.argv[1:]
format_string = None
output = None
index = 0
while index < len(args):
    argument = args[index]
    if argument == "--quiet":
        index += 1
    elif argument == "--format":
        format_string = args[index + 1]
        index += 2
    elif argument == "--output":
        output = args[index + 1]
        index += 2
    elif argument == "--":
        index += 1
        break
    else:
        raise SystemExit(f"unexpected fake-time argument: {argument}")

if format_string is None or output is None or index >= len(args):
    raise SystemExit("incomplete fake-time invocation")

started = time.perf_counter()
process = subprocess.run(args[index:], check=False)
elapsed = os.environ.get("FAKE_ELAPSED_S", f"{time.perf_counter() - started:.6f}")
rss = os.environ.get("FAKE_RSS_KIB", "100")
if os.environ.get("FAKE_TIME_MODE") == "malformed":
    report = "malformed measurement"
else:
    report = (
        format_string.replace("%e", elapsed)
        .replace("%M", rss)
        .replace("%x", str(process.returncode))
    )
Path(output).write_text(report + "\n", encoding="utf-8")
raise SystemExit(process.returncode)
"""


FAKE_VIPER = r"""
#!/usr/bin/env python3
import os
import sys
import time
from pathlib import Path

if len(sys.argv) != 3 or sys.argv[1] != "solve":
    raise SystemExit(64)
source = Path(sys.argv[2])
sleep_s = float(os.environ.get("FAKE_SLEEP_S", "0"))
if sleep_s:
    time.sleep(sleep_s)
result = os.environ.get("RESULT_OVERRIDE", source.read_text(encoding="utf-8").strip())
log_path = os.environ.get("ORDER_LOG")
if log_path:
    with Path(log_path).open("a", encoding="utf-8") as handle:
        handle.write(
            "|".join(
                [
                    os.environ.get("ARM_LABEL", "missing"),
                    source.name,
                    os.environ.get("BASE_ONLY", "-"),
                    os.environ.get("CANDIDATE_ONLY", "-"),
                ]
            )
            + "\n"
        )
print(result)
raise SystemExit(int(os.environ.get("FAKE_EXIT_CODE", "0")))
"""


def write_executable(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(0o755)


class ComparatorCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.fake_time = self.root / "fake-time"
        self.baseline = self.root / "baseline"
        self.candidate = self.root / "candidate"
        write_executable(self.fake_time, FAKE_TIME)
        write_executable(self.baseline, FAKE_VIPER)
        write_executable(self.candidate, FAKE_VIPER)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_manifest(self, statuses: list[str]) -> Path:
        manifest = self.root / "manifest.jsonl"
        rows = []
        for index, status in enumerate(statuses):
            source = self.root / f"case-{index}.smt2"
            source.write_text(status + "\n", encoding="utf-8")
            rows.append(
                {
                    "id": index,
                    "path": str(source),
                    "relative_path": f"suite/{source.name}",
                    "logic": "QF_UF",
                    "status": status,
                }
            )
        manifest.write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        return manifest

    def run_comparator(
        self,
        manifest: Path,
        *,
        baseline_env: list[str] | None = None,
        candidate_env: list[str] | None = None,
        timeout: float = 2.0,
        repeats: int = 1,
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        csv_path = self.root / "resources.csv"
        summary_path = self.root / "resources.json"
        command = [
            sys.executable,
            str(SCRIPT),
            str(manifest),
            "--baseline",
            str(self.baseline),
            "--candidate",
            str(self.candidate),
            "--time-executable",
            str(self.fake_time),
            "--timeout",
            str(timeout),
            "--repeats",
            str(repeats),
            "--out",
            str(csv_path),
            "--summary",
            str(summary_path),
        ]
        for value in baseline_env or []:
            command.extend(["--baseline-env", value])
        for value in candidate_env or []:
            command.extend(["--candidate-env", value])
        environment = os.environ.copy()
        environment.pop("BASE_ONLY", None)
        environment.pop("CANDIDATE_ONLY", None)
        completed = subprocess.run(
            command,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return completed, csv_path, summary_path

    def test_emits_resource_artifacts_and_alternates_isolated_arms(self) -> None:
        manifest = self.write_manifest(["sat", "unsat"])
        order_log = self.root / "order.log"

        completed, csv_path, summary_path = self.run_comparator(
            manifest,
            repeats=2,
            baseline_env=[
                "ARM_LABEL=baseline",
                "BASE_ONLY=set",
                "FAKE_ELAPSED_S=1.25",
                "FAKE_RSS_KIB=1200",
                f"ORDER_LOG={order_log}",
            ],
            candidate_env=[
                "ARM_LABEL=candidate",
                "CANDIDATE_ONLY=set",
                "FAKE_ELAPSED_S=0.75",
                "FAKE_RSS_KIB=900",
                f"ORDER_LOG={order_log}",
            ],
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        with csv_path.open(newline="", encoding="utf-8") as handle:
            records = list(csv.DictReader(handle))
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
        self.assertEqual([record["order"] for record in records], ["0", "1"] * 4)
        self.assertTrue(all(record["correct"] == "True" for record in records))
        self.assertEqual(
            {
                record["peak_rss_kib"]
                for record in records
                if record["label"] == "baseline"
            },
            {"1200"},
        )
        self.assertEqual(
            {
                record["elapsed_s"]
                for record in records
                if record["label"] == "candidate"
            },
            {"0.75"},
        )

        log_lines = order_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            [line.split("|", 1)[0] for line in log_lines],
            [record["label"] for record in records],
        )
        self.assertTrue(
            all(
                line.split("|")[2:] == ["set", "-"]
                for line in log_lines
                if line.startswith("baseline|")
            )
        )
        self.assertTrue(
            all(
                line.split("|")[2:] == ["-", "set"]
                for line in log_lines
                if line.startswith("candidate|")
            )
        )

        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertTrue(summary["valid"])
        self.assertEqual(summary["instances"], 2)
        self.assertEqual(summary["observations"], 8)
        self.assertEqual(summary["baseline"]["total_elapsed_s"], 5.0)
        self.assertEqual(summary["candidate"]["total_elapsed_s"], 3.0)
        self.assertEqual(summary["baseline"]["max_peak_rss_kib"], 1200)
        self.assertEqual(summary["candidate"]["max_peak_rss_kib"], 900)
        self.assertEqual(summary["candidate_to_baseline_peak_rss_ratio"], 0.75)
        self.assertEqual(summary["baseline_env_overrides"]["BASE_ONLY"], "set")
        self.assertNotIn("CANDIDATE_ONLY", summary["baseline_env_overrides"])

    def test_status_mismatch_is_reported_and_fails_validation(self) -> None:
        manifest = self.write_manifest(["unsat"])
        completed, csv_path, summary_path = self.run_comparator(
            manifest,
            candidate_env=["RESULT_OVERRIDE=sat", "FAKE_RSS_KIB=80"],
        )

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertTrue(csv_path.is_file())
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertFalse(summary["valid"])
        self.assertEqual(summary["status"], "invalid")
        self.assertEqual(
            summary["status_mismatches"],
            [
                {
                    "relative_path": "suite/case-0.smt2",
                    "label": "candidate",
                    "repeat": 0,
                    "expected_status": "unsat",
                    "result": "sat",
                    "exit_code": 0,
                }
            ],
        )

    def test_malformed_time_record_publishes_no_artifacts(self) -> None:
        manifest = self.write_manifest(["sat"])
        completed, csv_path, summary_path = self.run_comparator(
            manifest,
            baseline_env=["FAKE_TIME_MODE=malformed"],
        )

        self.assertEqual(completed.returncode, 4)
        self.assertIn("invalid baseline measurement", completed.stderr)
        self.assertFalse(csv_path.exists())
        self.assertFalse(summary_path.exists())

    def test_timeout_terminates_measurement_and_publishes_no_artifacts(self) -> None:
        manifest = self.write_manifest(["sat"])
        started = time.monotonic()
        completed, csv_path, summary_path = self.run_comparator(
            manifest,
            baseline_env=["FAKE_SLEEP_S=5"],
            timeout=0.1,
        )

        self.assertEqual(completed.returncode, 4)
        self.assertIn("timed out after 0.1s", completed.stderr)
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertFalse(csv_path.exists())
        self.assertFalse(summary_path.exists())


class InputValidationTests(unittest.TestCase):
    def test_manifest_rejects_non_decisive_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = Path(temp_dir) / "manifest.jsonl"
            manifest.write_text(
                json.dumps(
                    {
                        "path": "/tmp/example.smt2",
                        "relative_path": "example.smt2",
                        "status": "unknown",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(COMPARE.ManifestError, "must be sat or unsat"):
                COMPARE.read_manifest(manifest)

    def test_measurement_parser_rejects_extra_or_non_finite_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            measurement = Path(temp_dir) / "measurement.txt"
            for value in (
                f"{COMPARE.MEASUREMENT_PREFIX}\t1.0\t123\t0\nextra\n",
                f"{COMPARE.MEASUREMENT_PREFIX}\tnan\t123\t0\n",
                f"{COMPARE.MEASUREMENT_PREFIX}\t1.0\t12.5\t0\n",
            ):
                measurement.write_text(value, encoding="utf-8")
                with self.assertRaises(COMPARE.MeasurementError):
                    COMPARE.parse_measurement(measurement)


if __name__ == "__main__":
    unittest.main()
