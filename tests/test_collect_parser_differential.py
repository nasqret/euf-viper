from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench" / "collect_parser_differential.py"
WMI_SCRIPT = ROOT / "scripts" / "wmi" / "euf_viper_parser_differential.sbatch"
SPEC = importlib.util.spec_from_file_location("collect_parser_differential", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
COLLECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECTOR)


FAKE_PARSER = r"""#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

if len(sys.argv) != 3 or sys.argv[1] != "parse-check":
    print("expected parse-check FILE", file=sys.stderr)
    raise SystemExit(64)
payload = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
mode = os.environ.get("EUF_VIPER_PARSER_MODE")
if mode != payload["expected_mode"]:
    print(f"unexpected mode {mode!r}", file=sys.stderr)
    raise SystemExit(65)
if os.environ.get("EUF_VIPER_PARSER") is not None:
    print("legacy parser environment leaked into candidate", file=sys.stderr)
    raise SystemExit(66)
if payload.get("sleep"):
    time.sleep(payload["sleep"])
if payload.get("error"):
    print(payload["error"], file=sys.stderr)
    raise SystemExit(payload.get("exit_code", 2))
if payload.get("malformed"):
    print("not a diagnostic")
    raise SystemExit(0)

route = payload.get("route", "stream" if mode == "stream" else "shadow-match")
fallback = payload.get("fallback_reason", "none")
status = "fallback" if fallback != "none" else "ok"
print(
    f"parse_status={status} parser_mode={mode} "
    f"parser_route={route} fallback_reason={fallback}"
)
"""


def write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


class DiagnosticTests(unittest.TestCase):
    def test_accepts_stable_direct_and_fallback_records(self) -> None:
        self.assertEqual(
            COLLECTOR.parse_diagnostic(
                "parse_status=ok parser_mode=shadow "
                "parser_route=shadow-match fallback_reason=none\n"
            ),
            {
                "parse_status": "ok",
                "parser_mode": "shadow",
                "parser_route": "shadow-match",
                "fallback_reason": "none",
            },
        )
        self.assertEqual(
            COLLECTOR.parse_diagnostic(
                "parse_status=fallback parser_mode=stream "
                "parser_route=tree-fallback fallback_reason=unsupported_command\n"
            )["fallback_reason"],
            "unsupported_command",
        )

    def test_rejects_missing_duplicate_and_inconsistent_fields(self) -> None:
        malformed = [
            "",
            "parse_status=ok parser_mode=stream parser_route=stream",
            (
                "parse_status=ok parse_status=ok parser_mode=stream "
                "parser_route=stream fallback_reason=none"
            ),
            (
                "parse_status=ok parser_mode=stream "
                "parser_route=tree-fallback fallback_reason=unsupported_command"
            ),
            (
                "parse_status=fallback parser_mode=shadow "
                "parser_route=shadow-match fallback_reason=unsupported_command"
            ),
            (
                "parse_status=ok parser_mode=tree "
                "parser_route=stream fallback_reason=none"
            ),
        ]
        for diagnostic in malformed:
            with self.subTest(diagnostic=diagnostic):
                with self.assertRaises(COLLECTOR.HarnessError):
                    COLLECTOR.parse_diagnostic(diagnostic)


class CollectionTests(unittest.TestCase):
    def test_collects_manifest_in_order_and_forwards_explicit_candidate_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "corpus"
            binary = root / "fake-viper"
            manifest = root / "manifest.jsonl"
            write_executable(binary, FAKE_PARSER)
            corpus.mkdir()
            fixtures = [
                (
                    "direct.smt2",
                    {"expected_mode": "stream", "route": "stream"},
                ),
                (
                    "fallback.smt2",
                    {
                        "expected_mode": "stream",
                        "route": "tree-fallback",
                        "fallback_reason": "term_valued_ite_or_let",
                    },
                ),
            ]
            rows = []
            for index, (name, payload) in enumerate(fixtures, 1):
                (corpus / name).write_text(json.dumps(payload), encoding="utf-8")
                rows.append(
                    {
                        "id": index,
                        "relative_path": name,
                        "status": "sat",
                    }
                )
            manifest.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )

            records, summary = COLLECTOR.collect_manifest(
                manifest,
                binary,
                "stream",
                timeout_s=1.0,
                jobs=2,
                benchmark_root=corpus,
            )

            self.assertEqual(
                [record["relative_path"] for record in records],
                ["direct.smt2", "fallback.smt2"],
            )
            self.assertTrue(all(record["status"] == "ok" for record in records))
            self.assertEqual(summary["candidate_parser_mode"], "stream")
            self.assertEqual(summary["successful"], 2)
            self.assertEqual(summary["fallbacks"], 1)
            self.assertEqual(
                summary["routes"], {"stream": 1, "tree-fallback": 1}
            )
            self.assertEqual(
                summary["fallback_reasons"], {"term_valued_ite_or_let": 1}
            )

    def test_classifies_parser_diagnostic_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary = root / "fake-viper"
            source = root / "bad.smt2"
            manifest = root / "manifest.jsonl"
            write_executable(binary, FAKE_PARSER)
            source.write_text(
                json.dumps({"expected_mode": "shadow", "malformed": True}),
                encoding="utf-8",
            )
            manifest.write_text(
                json.dumps(
                    {
                        "relative_path": source.name,
                        "path": str(source),
                        "status": "sat",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            records, summary = COLLECTOR.collect_manifest(
                manifest,
                binary,
                "shadow",
                timeout_s=1.0,
                jobs=1,
                benchmark_root=None,
            )

            self.assertEqual(records[0]["failure_kind"], "diagnostic_error")
            self.assertEqual(summary["errors"], 1)
            self.assertEqual(summary["successful"], 0)


class WmiHarnessTests(unittest.TestCase):
    def run_wrapper(self, mode: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory() as temp_dir:
            work = Path(temp_dir)
            capture = work / "arguments.json"
            recorder = r"""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

Path(os.environ["PARSER_ARGUMENT_CAPTURE"]).write_text(
    json.dumps(sys.argv[1:]), encoding="utf-8"
)
"""
            write_executable(
                work / "scripts" / "bench" / "collect_parser_differential.py",
                recorder,
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "SLURM_SUBMIT_DIR": str(work),
                    "SLURM_JOB_ID": "123",
                    "SLURM_CPUS_PER_TASK": "4",
                    "EUF_VIPER_PARSER_MODE": mode,
                    "EUF_VIPER_PARSER_MANIFEST": "/corpus/full.jsonl",
                    "EUF_VIPER_PARSER_BENCHMARK_ROOT": "/corpus/QF_UF",
                    "EUF_VIPER_PARSER_BINARY": "/opt/euf-viper",
                    "PARSER_ARGUMENT_CAPTURE": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(WMI_SCRIPT)],
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )
            arguments = (
                json.loads(capture.read_text(encoding="utf-8"))
                if capture.exists()
                else []
            )
            return completed, arguments

    def test_forwards_explicit_candidate_parser_mode(self) -> None:
        completed, arguments = self.run_wrapper("stream")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        mode_index = arguments.index("--candidate-parser-mode")
        self.assertEqual(arguments[mode_index + 1], "stream")
        self.assertEqual(arguments[0], "/corpus/full.jsonl")

    def test_rejects_invalid_parser_mode_before_collection(self) -> None:
        completed, arguments = self.run_wrapper("facts")
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(arguments, [])
        self.assertIn("must be tree, shadow, or stream", completed.stderr)


if __name__ == "__main__":
    unittest.main()
